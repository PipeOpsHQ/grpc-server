package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"time"

	pb "github.com/PipeOpsHQ/grpc-server/internal/agent"
	"github.com/PipeOpsHQ/grpc-server/internal/auth"
	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/status"
)

type streamInfo struct {
	stream   pb.AgentService_CommunicateServer
	done     chan struct{}
	cancelFn context.CancelFunc // Add cancel function to properly cleanup
}

type server struct {
	pb.UnimplementedAgentServiceServer
	mu      sync.RWMutex
	streams map[string]*streamInfo
	auth    *auth.AuthManager
}

func (s *server) Authenticate(ctx context.Context, req *pb.AuthRequest) (*pb.AuthResponse, error) {
	if !s.auth.ValidateCredentials(req.ServiceAccount, req.Token) {
		return nil, status.Errorf(codes.Unauthenticated, "invalid service account or token")
	}
	return &pb.AuthResponse{}, nil
}

func (s *server) Communicate(stream pb.AgentService_CommunicateServer) error {
	ctx := stream.Context()
	serviceAccountID, ok := ctx.Value("service_account_id").(string)
	if !ok {
		return status.Errorf(codes.Unauthenticated, "missing service account ID in context")
	}

	// Create a cancellable context for this stream
	streamCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	// First message must contain agent ID
	msg, err := stream.Recv()
	if err != nil {
		log.Printf("Error receiving initial message: %v", err)
		return err
	}

	agentID := msg.From
	if agentID == "" {
		log.Printf("Error: received empty agent ID")
		return fmt.Errorf("empty agent ID")
	}

	// Register the agent
	if err := s.registerAgent(serviceAccountID, stream, cancel); err != nil {
		log.Printf("Error registering agent %s: %v", agentID, err)
		return err
	}
	defer s.unregisterAgent(serviceAccountID)

	log.Printf("Agent %s connected", agentID)

	// Message processing loop
	for {
		select {
		case <-streamCtx.Done():
			log.Printf("Stream context cancelled for agent %s", agentID)
			return streamCtx.Err()
		default:
			msg, err := stream.Recv()
			if err == io.EOF {
				log.Printf("Agent %s disconnected", agentID)
				return nil
			}
			if err != nil {
				log.Printf("Error receiving message from %s: %v", agentID, err)
				return err
			}
			log.Printf("Received from %s: %s", msg.From, msg.Content)
		}
	}
}

func (s *server) registerAgent(serviceAccountID string, stream pb.AgentService_CommunicateServer, cancel context.CancelFunc) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.streams == nil {
		s.streams = make(map[string]*streamInfo)
	}

	// Safely cleanup existing stream if it exists
	if existing, exists := s.streams[serviceAccountID]; exists {
		existing.cancelFn() // Cancel the context first
		close(existing.done)
		// Wait a small amount of time for cleanup
		time.Sleep(100 * time.Millisecond)
	}

	s.streams[serviceAccountID] = &streamInfo{
		stream:   stream,
		done:     make(chan struct{}),
		cancelFn: cancel,
	}

	log.Printf("Registered agent %s", serviceAccountID)
	return nil
}

func (s *server) unregisterAgent(serviceAccountID string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if streamInfo, exists := s.streams[serviceAccountID]; exists {
		streamInfo.cancelFn() // Cancel context first
		// Use select to safely close channel
		select {
		case <-streamInfo.done: // Channel already closed
		default:
			close(streamInfo.done)
		}
		delete(s.streams, serviceAccountID)
		log.Printf("Agent %s unregistered", serviceAccountID)
	}
}

func (s *server) broadcastMessage(content string) {
	s.mu.RLock()
	activeStreams := make(map[string]*streamInfo, len(s.streams))
	for id, stream := range s.streams {
		activeStreams[id] = stream
	}
	s.mu.RUnlock()

	var wg sync.WaitGroup
	for agentID, si := range activeStreams {
		wg.Add(1)
		go func(agentID string, info *streamInfo) {
			defer wg.Done()

			uniqueMsg := fmt.Sprintf("%s - Unique message for agent %s: %s - timestamp: %d",
				content,
				agentID,
				uuid.New().String(),
				time.Now().UnixNano(),
			)

			msg := &pb.Message{
				From:    "Server",
				To:      agentID,
				Content: uniqueMsg,
			}

			// Use context with timeout for sending messages
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			done := make(chan error, 1)
			go func() {
				done <- info.stream.Send(msg)
			}()

			select {
			case err := <-done:
				if err != nil {
					log.Printf("Error broadcasting to %s: %v", agentID, err)
					go s.unregisterAgent(agentID) // Unregister asynchronously to avoid deadlock
				} else {
					log.Printf("Unique message sent to %s: %s", agentID, uniqueMsg)
				}
			case <-ctx.Done():
				log.Printf("Broadcast to %s timed out", agentID)
				go s.unregisterAgent(agentID) // Unregister asynchronously to avoid deadlock
			case <-info.done:
				return
			}
		}(agentID, si)
	}
	wg.Wait()
}

func (s *server) startBroadcaster() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		s.broadcastMessage("Hello, agents! This is a broadcast from the server.")
	}
}

func main() {
	listener, err := net.Listen("tcp", "0.0.0.0:50054")
	if err != nil {
		log.Fatalf("Failed to listen on port 50054: %v", err)
	}

	authManager := auth.NewAuthManager("TEST_SECRET", 1*time.Hour)

	grpcServer := grpc.NewServer(
		grpc.UnaryInterceptor(authManager.UnaryAuthInterceptor),
		grpc.StreamInterceptor(authManager.StreamAuthInterceptor),
		grpc.KeepaliveParams(keepalive.ServerParameters{
			MaxConnectionIdle: 15 * time.Minute,
			MaxConnectionAge:  2 * time.Hour,
			Time:              5 * time.Minute,
			Timeout:           20 * time.Second,
		}),
		grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{
			MinTime:             1 * time.Minute,
			PermitWithoutStream: true,
		}),
	)

	s := &server{auth: authManager}
	pb.RegisterAgentServiceServer(grpcServer, s)

	go s.startBroadcaster()

	log.Println("Server is listening on port 50054")
	if err := grpcServer.Serve(listener); err != nil {
		log.Fatalf("Failed to serve: %v", err)
	}
}
