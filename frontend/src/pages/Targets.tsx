import React, { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { targetsApi } from '../api/client';
import { 
  Plus, Search, Filter, 
  Trash2, ExternalLink, Shield, ShieldAlert,
  Target as TargetIcon, Globe, Lock, Cpu
} from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';
import { VulnScoutSounds } from '../lib/sounds';

const Targets: React.FC = () => {
  const [targets, setTargets] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [searchTerm, setSearchTerm] = useState('');
  const [deletingId, setDeletingId] = useState<string | null>(null);

  useEffect(() => {
    fetchTargets();
  }, []);

  const fetchTargets = async () => {
    try {
      setLoading(true);
      const response = await targetsApi.list();
      setTargets(response.data.targets as any[] || []);
    } catch (error) {
      console.error('Failed to fetch targets:', error);
    } finally {
      setLoading(false);
    }
  };

  const filteredTargets = targets.filter(t => {
    const url = t.url || t.base_url || "";
    const name = t.name || "";
    return url.toLowerCase().includes(searchTerm.toLowerCase()) || 
           name.toLowerCase().includes(searchTerm.toLowerCase());
  });

  const handleDelete = async (id: string) => {
    VulnScoutSounds.play('buttonClick');
    if (!window.confirm('Are you sure you want to delete this target?')) return;
    try {
      setDeletingId(id);
      await targetsApi.delete(id);
      setTargets(targets.filter(t => (t.target_id || t.id) !== id));
    } catch (error) {
      console.error('Failed to delete target:', error);
    } finally {
      setDeletingId(null);
    }
  };

  return (
    <div className="p-4 sm:p-8 cyber-grid min-h-screen">
      <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4 mb-8">
        <div>
          <h1 className="text-3xl font-bold tracking-tight mb-1 flex items-center gap-2">
            <TargetIcon className="text-primary h-8 w-8" />
            Targets Registry
          </h1>
          <p className="text-muted-foreground">Manage and audit scanning perimeters.</p>
        </div>
        
        <Link 
          to="/targets/new"
          onClick={() => VulnScoutSounds.play('buttonClick')}
          className="flex items-center gap-2 bg-primary hover:bg-primary/90 text-white px-4 py-2 rounded-md font-medium transition-all neon-blue"
        >
          <Plus size={18} />
          Add New Target
        </Link>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-12 gap-6 mb-6">
        <div className="lg:col-span-8 relative">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 text-muted-foreground" size={18} />
          <input 
            type="text"
            placeholder="Search by URL, hostname, or target name..."
            className="w-full bg-card border border-border rounded-lg py-2.5 pl-10 pr-4 focus:outline-none focus:ring-2 focus:ring-primary/50 transition-all"
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
          />
        </div>
        <div className="lg:col-span-4 flex gap-2">
          <button 
             onClick={() => VulnScoutSounds.play('buttonClick')}
             className="flex-1 flex items-center justify-center gap-2 bg-secondary text-foreground border border-border py-2 px-4 rounded-lg hover:bg-secondary/80 transition-all"
          >
            <Filter size={18} />
            Filters
          </button>
          <button 
            onClick={() => {
                VulnScoutSounds.play('radarPing');
                fetchTargets();
            }}
            className="flex items-center justify-center w-11 bg-secondary text-foreground border border-border rounded-lg hover:bg-secondary/80 transition-all"
          >
            <Cpu size={18} className={loading ? 'animate-spin' : ''} />
          </button>
        </div>
      </div>

      {loading && targets.length === 0 ? (
        <div className="flex flex-col items-center justify-center py-20">
          <div className="w-12 h-12 border-4 border-primary/20 border-t-primary rounded-full animate-spin mb-4"></div>
          <p className="text-muted-foreground animate-pulse font-mono uppercase tracking-widest text-xs">Initialising Surveillance...</p>
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-6">
          <AnimatePresence mode="popLayout">
            {filteredTargets.map((target) => (
              <motion.div
                key={target.target_id}
                layout
                initial={{ opacity: 0, scale: 0.95, y: 20 }}
                animate={{ opacity: 1, scale: 1, y: 0 }}
                exit={{ opacity: 0, scale: 0.9, y: 10 }}
                className="glass rounded-xl p-5 relative group overflow-hidden"
              >
                <div className="absolute top-0 right-0 p-2 opacity-0 group-hover:opacity-100 transition-opacity">
                  <button 
                    onClick={() => handleDelete(target.target_id)}
                    disabled={deletingId === target.target_id}
                    className="p-1.5 text-muted-foreground hover:text-destructive transition-colors"
                  >
                    <Trash2 size={16} />
                  </button>
                </div>

                <div className="flex items-start gap-4 mb-4">
                  <div className={`p-3 rounded-lg ${target.is_https ? 'bg-success/10 text-success neon-green' : 'bg-warning/10 text-warning'}`}>
                    {target.is_https ? <Lock size={20} /> : <ShieldAlert size={20} />}
                  </div>
                  <div className="flex-1 min-w-0">
                    <h3 className="font-bold truncate group-hover:text-primary transition-colors cursor-pointer">
                      {target.name || target.url}
                    </h3>
                    <div className="flex items-center gap-1.5 text-xs text-muted-foreground mt-0.5">
                      <Globe size={12} />
                      <span className="truncate">{target.url}</span>
                      <a href={target.url} target="_blank" rel="noreferrer" className="hover:text-primary">
                        <ExternalLink size={12} />
                      </a>
                    </div>
                  </div>
                </div>

                <div className="grid grid-cols-2 gap-3 mb-4">
                  <div className="bg-secondary/50 rounded-md py-2 px-3 border border-border/50">
                    <span className="block text-[10px] uppercase tracking-wider text-muted-foreground mb-1">Industry</span>
                    <span className="text-xs font-medium capitalize">{target.industry || 'General'}</span>
                  </div>
                  <div className="bg-secondary/50 rounded-md py-2 px-3 border border-border/50">
                    <span className="block text-[10px] uppercase tracking-wider text-muted-foreground mb-1">Created</span>
                    <span className="text-xs font-medium">{new Date(target.created_at).toLocaleDateString()}</span>
                  </div>
                </div>

                <div className="flex flex-wrap gap-2">
                  {target.is_ea_target && (
                    <span className="bg-accent/10 text-accent text-[10px] font-bold px-2 py-1 rounded border border-accent/20 flex items-center gap-1">
                      <Shield size={10} /> EA TARGET
                    </span>
                  )}
                  {target.tags?.map((tag: string) => (
                    <span key={tag} className="bg-secondary text-muted-foreground text-[10px] font-medium px-2 py-1 rounded border border-border">
                      {tag.toUpperCase()}
                    </span>
                  ))}
                </div>
                
                <div className="mt-5 pt-4 border-t border-border flex items-center justify-between">
                  <div className="flex -space-x-2">
                    {[1, 2, 3].map(i => (
                      <div key={i} className="w-6 h-6 rounded-full bg-muted border-2 border-card flex items-center justify-center text-[10px] text-muted-foreground">
                        S{i}
                      </div>
                    ))}
                  </div>
                  <Link 
                    to={`/scans/new?target=${target.target_id}`}
                    onClick={() => VulnScoutSounds.play('buttonClick')}
                    className="text-xs font-bold text-primary hover:underline flex items-center gap-1"
                  >
                    INITIATE SCAN <Cpu size={12} />
                  </Link>
                </div>
              </motion.div>
            ))}
          </AnimatePresence>
        </div>
      )}

      {!loading && filteredTargets.length === 0 && (
        <div className="glass rounded-2xl border-dashed border-2 p-12 text-center max-w-xl mx-auto mt-12 bg-transparent">
          <div className="bg-muted w-16 h-16 rounded-full flex items-center justify-center mx-auto mb-6">
            <ShieldAlert className="text-muted-foreground" size={32} />
          </div>
          <h3 className="text-lg font-bold mb-2">No perimeters registered</h3>
          <p className="text-muted-foreground mb-8">
            You haven't defined any targets within your authorised scope yet. 
            Add your first target to begin security auditing.
          </p>
          <Link 
            to="/targets/new"
            onClick={() => VulnScoutSounds.play('buttonClick')}
            className="inline-flex items-center gap-2 bg-primary text-white px-6 py-3 rounded-lg font-bold hover:bg-primary/90 transition-all neon-blue"
          >
            <Plus size={20} /> Deploy New Fingerprint
          </Link>
        </div>
      )}
    </div>
  );
};

export default Targets;
