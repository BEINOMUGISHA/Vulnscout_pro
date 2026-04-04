import React, { useRef, useMemo } from 'react';
import { Canvas, useFrame } from '@react-three/fiber';
import { OrbitControls, MeshDistortMaterial, Float, ContactShadows, Text } from '@react-three/drei';
import * as THREE from 'three';

const RiskZone = ({ position, severity = 0.5 }: { position: [number, number, number], severity?: number }) => {
  const meshRef = useRef<THREE.Mesh>(null);
  
  useFrame((state) => {
    if (meshRef.current) {
      const pulse = 1 + Math.sin(state.clock.elapsedTime * 6) * 0.1;
      meshRef.current.scale.set(pulse, pulse, pulse);
    }
  });

  return (
    <mesh position={position}>
      <sphereGeometry args={[severity * 0.3, 16, 16]} />
      <meshStandardMaterial 
        color="#ef4444" 
        emissive="#ef4444" 
        emissiveIntensity={4 * severity}
        transparent
        opacity={0.8}
      />
    </mesh>
  );
};

const RiskScene = ({ riskScore = 50 }: { riskScore?: number }) => {
  const zones = useMemo(() => {
    const count = Math.floor(riskScore / 10);
    return Array.from({ length: count }).map((_, i) => {
      const phi = Math.acos(-1 + (2 * i) / count);
      const theta = Math.sqrt(count * Math.PI) * phi;
      const x = 1.6 * Math.cos(theta) * Math.sin(phi);
      const y = 1.6 * Math.sin(theta) * Math.sin(phi);
      const z = 1.6 * Math.cos(phi);
      return { pos: [x, y, z], sev: 0.3 + Math.random() * 0.7 };
    });
  }, [riskScore]);

  return (
    <>
      <ambientLight intensity={0.4} />
      <spotLight position={[10, 10, 10]} angle={0.15} penumbra={1} intensity={2} />
      <pointLight position={[-10, -10, -10]} color="#3b82f6" intensity={1} />
      
      <Float speed={3} rotationIntensity={1} floatIntensity={1}>
        <mesh>
          <sphereGeometry args={[1.5, 64, 64]} />
          <MeshDistortMaterial
            color={riskScore > 70 ? "#450a0a" : "#0f172a"}
            roughness={0.2}
            metalness={0.9}
            distort={0.4}
            speed={4}
            emissive={riskScore > 70 ? "#ef4444" : "#1e293b"}
            emissiveIntensity={riskScore > 70 ? 0.3 : 0.1}
          />
        </mesh>
      </Float>

      {zones.map((z, i) => (
        <RiskZone key={i} position={z.pos as any} severity={z.sev} />
      ))}

      <ContactShadows
        position={[0, -2.5, 0]}
        opacity={0.4}
        scale={10}
        blur={2}
        far={4.5}
      />

      <OrbitControls enableZoom={false} />
    </>
  );
};

const RiskSphere: React.FC<{ riskScore: number }> = ({ riskScore }) => {
  return (
    <div className="w-full h-[400px] bg-slate-950/20 rounded-3xl border border-white/5 overflow-hidden relative group">
      <div className="absolute top-4 left-4 z-10">
        <div className="text-[10px] font-black uppercase tracking-[0.2em] text-red-500 mb-1">Risk Surface Analysis</div>
        <div className="text-xs font-mono text-white/50">GEOMETRIC ANOMALY DETECTION: {riskScore}%</div>
      </div>
      <Canvas 
        camera={{ position: [0, 0, 5], fov: 40 }}
        gl={{ powerPreference: 'high-performance', antialias: true }}
      >
        <RiskScene riskScore={riskScore} />
      </Canvas>
      <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 pointer-events-none opacity-10 group-hover:opacity-20 transition-opacity">
        <div className="w-[300px] h-[300px] border-[0.5px] border-white rounded-full animate-[spin_10s_linear_infinite]"></div>
        <div className="absolute inset-0 w-[300px] h-[300px] border-[0.5px] border-white rounded-full animate-[spin_15s_linear_infinite] opacity-50"></div>
      </div>
    </div>
  );
};

export default RiskSphere;
