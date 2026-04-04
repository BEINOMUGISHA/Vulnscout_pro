import React, { useRef, useMemo } from 'react';
import { Canvas, useFrame } from '@react-three/fiber';
import { OrbitControls, Sphere, MeshDistortMaterial, Float, Line, Stars } from '@react-three/drei';
import * as THREE from 'three';

const ServerNode = ({ position, color = "#3b82f6", pulse = false }: { position: [number, number, number], color?: string, pulse?: boolean }) => {
  const meshRef = useRef<THREE.Mesh>(null);
  
  useFrame((state) => {
    if (pulse && meshRef.current) {
      const s = 1 + Math.sin(state.clock.elapsedTime * 4) * 0.2;
      meshRef.current.scale.set(s, s, s);
    }
  });

  return (
    <mesh position={position} ref={meshRef}>
      <sphereGeometry args={[0.1, 16, 16]} />
      <meshStandardMaterial 
        color={color} 
        emissive={color} 
        emissiveIntensity={pulse ? 2 : 1}
      />
    </mesh>
  );
};

const AttackPath = ({ start, end, progress }: { start: THREE.Vector3, end: THREE.Vector3, progress: number }) => {
  const points = useMemo(() => {
    const curve = new THREE.QuadraticBezierCurve3(
      start,
      new THREE.Vector3().addVectors(start, end).multiplyScalar(0.5).add(new THREE.Vector3(0, 1, 0)),
      end
    );
    return curve.getPoints(50);
  }, [start, end]);

  return (
    <Line
      points={points}
      color="#ef4444"
      lineWidth={1}
      transparent
      opacity={0.5}
    />
  );
};

const Scene = () => {
  const nodes = useMemo(() => [
    { pos: [2, 0, 0], color: "#3b82f6", pulse: true },
    { pos: [-1.5, 1, 1], color: "#10b981", pulse: false },
    { pos: [0, -1.8, 0.5], color: "#3b82f6", pulse: false },
    { pos: [-1, -1, -2], color: "#f59e0b", pulse: true },
    { pos: [1, 2, -1], color: "#ef4444", pulse: true },
  ], []);

  return (
    <>
      <ambientLight intensity={0.5} />
      <pointLight position={[10, 10, 10]} intensity={1} />
      <Stars radius={100} depth={50} count={5000} factor={4} saturation={0} fade speed={1} />
      
      <Float speed={2} rotationIntensity={0.5} floatIntensity={0.5}>
        <Sphere args={[1.5, 64, 64]}>
          <MeshDistortMaterial
            color="#1e293b"
            roughness={0.1}
            metalness={0.8}
            distort={0.2}
            speed={2}
            wireframe
          />
        </Sphere>
      </Float>

      {nodes.map((n, i) => (
        <ServerNode key={i} position={n.pos as any} color={n.color} pulse={n.pulse} />
      ))}

      <AttackPath 
        start={new THREE.Vector3(2, 0, 0)} 
        end={new THREE.Vector3(1, 2, -1)} 
        progress={0} 
      />
      <AttackPath 
        start={new THREE.Vector3(-1, -1, -2)} 
        end={new THREE.Vector3(1, 2, -1)} 
        progress={0} 
      />

      <OrbitControls enableZoom={false} autoRotate autoRotateSpeed={0.5} />
    </>
  );
};

const ThreatMap: React.FC = () => {
  return (
    <div className="w-full h-[400px] bg-slate-950/50 rounded-3xl border border-white/10 overflow-hidden relative group">
      <div className="absolute top-4 left-4 z-10">
        <div className="text-[10px] font-black uppercase tracking-[0.2em] text-primary mb-1">Live Threat Intel</div>
        <div className="text-xs font-mono text-white/50">CYBER-GEOPOLITICAL MAPPING ACTIVE</div>
      </div>
      <Canvas 
        camera={{ position: [0, 0, 5], fov: 45 }}
        gl={{ powerPreference: 'high-performance' }}
      >
        <Scene />
      </Canvas>
      <div className="absolute bottom-4 right-4 z-10 flex gap-2">
        <div className="flex items-center gap-1.5 px-3 py-1 bg-black/50 rounded-full border border-white/10">
          <div className="w-1.5 h-1.5 rounded-full bg-blue-500"></div>
          <span className="text-[8px] font-bold text-white/70 uppercase">Node</span>
        </div>
        <div className="flex items-center gap-1.5 px-3 py-1 bg-black/50 rounded-full border border-white/10">
          <div className="w-1.5 h-1.5 rounded-full bg-red-500 animate-pulse"></div>
          <span className="text-[8px] font-bold text-white/70 uppercase">Active Attack</span>
        </div>
      </div>
    </div>
  );
};

export default ThreatMap;
