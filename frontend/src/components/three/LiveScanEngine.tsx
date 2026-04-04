import React, { useRef, useMemo } from 'react';
import { Canvas, useFrame } from '@react-three/fiber';
import { OrbitControls, Points, PointMaterial, Line } from '@react-three/drei';
import * as THREE from 'three';

const AttackParticle = ({ start, end, speed = 1, color = "#ef4444" }: { start: THREE.Vector3, end: THREE.Vector3, speed?: number, color?: string }) => {
  const meshRef = useRef<THREE.Mesh>(null);
  const startTime = useMemo(() => Math.random() * 5, []);
  
  useFrame((state) => {
    if (meshRef.current) {
      const t = ((state.clock.elapsedTime + startTime) * speed) % 1;
      meshRef.current.position.lerpVectors(start, end, t);
      meshRef.current.scale.setScalar(1 - t * 0.5);
      meshRef.current.visible = t < 0.95;
    }
  });

  return (
    <mesh ref={meshRef}>
      <sphereGeometry args={[0.08, 8, 8]} />
      <meshStandardMaterial color={color} emissive={color} emissiveIntensity={2} />
    </mesh>
  );
};

const InfrastructureGrid = () => {
    return (
        <gridHelper args={[20, 20, 0x3b82f6, 0x1e293b]} rotation={[Math.PI / 2, 0, 0]} position={[0, 0, -5]} />
    );
};

const LiveScanScene = () => {
  const sources = useMemo(() => Array.from({ length: 5 }).map(() => new THREE.Vector3(-8 + Math.random() * 4, -4 + Math.random() * 8, -4)), []);
  const targets = useMemo(() => Array.from({ length: 3 }).map(() => new THREE.Vector3(4 + Math.random() * 4, -2 + Math.random() * 4, -4)), []);
  
  const attacks = useMemo(() => Array.from({ length: 15 }).map(() => ({
    src: sources[Math.floor(Math.random() * sources.length)],
    tgt: targets[Math.floor(Math.random() * targets.length)],
    speed: 0.2 + Math.random() * 0.5,
    isFraud: Math.random() > 0.8
  })), [sources, targets]);

  return (
    <>
      <ambientLight intensity={0.5} />
      <pointLight position={[0, 0, 10]} intensity={1} />
      
      <InfrastructureGrid />

      {sources.map((pos, i) => (
        <mesh key={`src-${i}`} position={pos}>
          <boxGeometry args={[0.3, 0.3, 0.3]} />
          <meshStandardMaterial color="#3b82f6" emissive="#3b82f6" emissiveIntensity={0.5} />
        </mesh>
      ))}

      {targets.map((pos, i) => (
        <mesh key={`tgt-${i}`} position={pos}>
          <cylinderGeometry args={[0.4, 0.4, 0.1, 32]} />
          <meshStandardMaterial color="#10b981" emissive="#10b981" emissiveIntensity={0.5} />
        </mesh>
      ))}

      {attacks.map((a, i) => (
        <AttackParticle 
            key={i} 
            start={a.src} 
            end={a.tgt} 
            speed={a.speed} 
            color={a.isFraud ? "#f59e0b" : "#ef4444"} 
        />
      ))}

      <OrbitControls enableZoom={false} />
    </>
  );
};

const LiveScanEngine: React.FC = () => {
  return (
    <div className="w-full h-[400px] bg-black/40 rounded-3xl border border-white/10 overflow-hidden relative group">
      <div className="absolute top-4 left-4 z-10">
        <div className="text-[10px] font-black uppercase tracking-[0.2em] text-amber-500 mb-1">Live Scan Engine</div>
        <div className="text-xs font-mono text-white/50">FRAUD PATTERN DETECTION ENABLED (UG-FIN-01)</div>
      </div>
      <Canvas camera={{ position: [0, 0, 10], fov: 40 }}>
        <LiveScanScene />
      </Canvas>
      <div className="absolute bottom-4 left-4 z-10 space-y-2">
        <div className="flex items-center gap-4 text-[8px] font-black uppercase tracking-widest text-white/40">
            <span className="flex items-center gap-1"><div className="w-2 h-2 rounded-full bg-red-500"></div> Port Scan</span>
            <span className="flex items-center gap-1"><div className="w-2 h-2 rounded-full bg-amber-500"></div> Fraud Attempt</span>
            <span className="flex items-center gap-1"><div className="w-2 h-2 rounded-full bg-blue-500"></div> Source</span>
            <span className="flex items-center gap-1"><div className="w-2 h-2 rounded-full bg-emerald-500"></div> Destination</span>
        </div>
      </div>
    </div>
  );
};

export default LiveScanEngine;
