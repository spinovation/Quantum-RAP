import React, { useState, useEffect } from 'react';
import { 
  Calculator, 
  ListTodo,
  Sparkles
} from 'lucide-react';
import { calculateMoscaRisk } from '../utils/moscaMath';
import type { MoscaResult } from '../utils/moscaMath';

interface Milestone {
  id: string;
  quarter: string;
  title: string;
  description: string;
  completed: boolean;
}

export const MigrationPlanner: React.FC = () => {
  // Mosca calculator parameters
  const [shelfLife, setShelfLife] = useState(10); // S
  const [migrationTime, setMigrationTime] = useState(5); // Y
  const [collapseTime, setCollapseTime] = useState(12); // Z
  const [riskResult, setRiskResult] = useState<MoscaResult | null>(null);

  // Roadmap milestones
  const [milestones, setMilestones] = useState<Milestone[]>([
    {
      id: 'm1',
      quarter: 'Q1-Q2 2026',
      title: 'Cryptographic Discovery & Inventory',
      description: 'Catalog all public certificates, private keys, SSH configurations, and API ciphers across internal networks using QuarkShield scanners.',
      completed: true
    },
    {
      id: 'm2',
      quarter: 'Q3-Q4 2026',
      title: 'Data Classification & Mosca Assessment',
      description: 'Assess data storage shelf-life requirements and prioritize legacy databases containing sensitive PII for early post-quantum transition.',
      completed: false
    },
    {
      id: 'm3',
      quarter: 'Q1-Q4 2027',
      title: 'Hybrid Key Exchange Pilots',
      description: 'Enable hybrid TLS exchanges (ECDH + ML-KEM) in developer ingress endpoints. Pilot hybrid sntrup761 ssh credentials for admin channels.',
      completed: false
    },
    {
      id: 'm4',
      quarter: 'Q1-Q4 2028',
      title: 'Core Cryptographic Migration',
      description: 'Decommission legacy RSA-1024 and Triple DES ciphers. Re-key root certificate authorities using ML-DSA (Dilithium) standards.',
      completed: false
    },
    {
      id: 'm5',
      quarter: '2029-2030',
      title: 'Full Quantum-Resistant Posture',
      description: 'Enforce native PQC standard signatures on firmware updates, APIs, and microservices. Achieve 100% compliance across CNSA 2.0 timelines.',
      completed: false
    }
  ]);

  // Recalculate Mosca Risk whenever inputs change
  useEffect(() => {
    const result = calculateMoscaRisk(shelfLife, migrationTime, collapseTime);
    setRiskResult(result);
  }, [shelfLife, migrationTime, collapseTime]);

  const toggleMilestone = (id: string) => {
    setMilestones(prev => 
      prev.map(m => m.id === id ? { ...m, completed: !m.completed } : m)
    );
  };

  return (
    <>
      <div>
        <h2 style={{ fontSize: '1.8rem', fontWeight: 700, marginBottom: '0.5rem' }}>Post-Quantum Migration Planner</h2>
        <p>Formulate timelines and calculate mathematical risk margins using Mosca's Theorem.</p>
      </div>

      {/* Mosca Theorem Calculator Panel */}
      <div className="glass-panel" style={{ padding: '1.5rem' }}>
        <h3 style={{ fontSize: '1.15rem', marginBottom: '1.25rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <Calculator size={18} color="var(--accent-cyan)" /> Mosca's Theorem Risk Assessment
        </h3>
        
        <div className="mosca-calculator">
          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
            <div className="form-group">
              <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                <label>Data Shelf-Life ($S$): {shelfLife} years</label>
                <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Security lifespan of stored data</span>
              </div>
              <input 
                type="range" 
                min="1" 
                max="30" 
                value={shelfLife} 
                onChange={(e) => setShelfLife(Number(e.target.value))}
                style={{ accentColor: 'var(--accent-cyan)' }}
              />
            </div>

            <div className="form-group">
              <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                <label>Migration Time ($Y$): {migrationTime} years</label>
                <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Years needed to transition infrastructure</span>
              </div>
              <input 
                type="range" 
                min="1" 
                max="15" 
                value={migrationTime} 
                onChange={(e) => setMigrationTime(Number(e.target.value))}
                style={{ accentColor: 'var(--accent-purple)' }}
              />
            </div>

            <div className="form-group">
              <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                <label>Collapse Time ($Z$): {collapseTime} years</label>
                <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Projected time until a CRQC is developed</span>
              </div>
              <input 
                type="range" 
                min="5" 
                max="40" 
                value={collapseTime} 
                onChange={(e) => setCollapseTime(Number(e.target.value))}
                style={{ accentColor: 'var(--status-vulnerable)' }}
              />
            </div>
          </div>

          {/* Mosca Calculator Output */}
          {riskResult && (
            <div className="mosca-results">
              <div style={{ textAlign: 'center' }}>
                <span style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                  Risk Urgency Profile
                </span>
                <div className={`mosca-score-glowing ${riskResult.isThreatened ? 'risk' : 'safe'}`}>
                  {riskResult.priorityScore}
                  <span style={{ fontSize: '1.2rem', fontWeight: 500 }}>/100</span>
                </div>
                <div style={{ marginTop: '0.5rem' }}>
                  <span className={`badge ${
                    riskResult.riskLevel === 'critical' || riskResult.riskLevel === 'high' ? 'danger' : 
                    riskResult.riskLevel === 'medium' ? 'warning' : 'success'
                  }`}>
                    {riskResult.riskLevel.toUpperCase()} THREAT STATUS
                  </span>
                </div>
              </div>

              <div style={{ width: '100%', borderTop: '1px solid var(--border-normal)', paddingTop: '1rem', fontSize: '0.9rem' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '0.5rem' }}>
                  <span style={{ color: 'var(--text-secondary)' }}>Inequality ($S + Y &gt; Z$):</span>
                  <span style={{ fontFamily: 'var(--font-mono)', fontWeight: 600, color: riskResult.isThreatened ? 'var(--status-vulnerable)' : 'var(--status-secure)' }}>
                    {shelfLife} + {migrationTime} {riskResult.isThreatened ? '>' : '≤'} {collapseTime}
                  </span>
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '0.5rem' }}>
                  <span style={{ color: 'var(--text-secondary)' }}>Security Margin:</span>
                  <span style={{ 
                    fontWeight: 600, 
                    color: riskResult.isThreatened ? 'var(--status-vulnerable)' : 'var(--status-secure)' 
                  }}>
                    {riskResult.margin > 0 ? `+${riskResult.margin} Years Buffer` : `${riskResult.margin} Years Deficit`}
                  </span>
                </div>
              </div>
            </div>
          )}
        </div>

        {riskResult && (
          <div style={{ 
            marginTop: '1.5rem', 
            padding: '1rem', 
            borderRadius: '8px', 
            background: 'rgba(0,0,0,0.15)',
            borderLeft: `3px solid ${
              riskResult.riskLevel === 'critical' ? 'var(--status-vulnerable)' : 
              riskResult.riskLevel === 'high' ? 'var(--status-vulnerable)' : 
              riskResult.riskLevel === 'medium' ? 'var(--status-warning)' : 'var(--status-secure)'
            }`,
            fontSize: '0.92rem'
          }}>
            <div style={{ fontWeight: 600, marginBottom: '0.25rem', color: 'var(--text-primary)' }}>
              Mosca Formula Assessment:
            </div>
            <p style={{ marginBottom: '0.5rem' }}>{riskResult.assessmentSummary}</p>
            <div style={{ color: 'var(--accent-cyan)' }}>
              <span style={{ fontWeight: 600 }}>Action Required:</span> {riskResult.recommendation}
            </div>
          </div>
        )}
      </div>

      {/* Migration Roadmap timeline */}
      <div className="glass-panel" style={{ padding: '1.5rem' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.5rem', flexWrap: 'wrap', gap: '1rem' }}>
          <h3 style={{ fontSize: '1.15rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <ListTodo size={18} color="var(--accent-cyan)" /> PQC Transition Roadmap
          </h3>
          <span style={{ fontSize: '0.82rem', color: 'var(--text-secondary)', display: 'flex', alignItems: 'center', gap: '0.25rem' }}>
            <Sparkles size={12} color="var(--status-secure)" /> Check boxes to mark operational task completion.
          </span>
        </div>

        <div className="roadmap-timeline">
          {milestones.map((milestone) => (
            <div 
              key={milestone.id} 
              className={`timeline-node ${milestone.completed ? 'completed' : 'future'}`}
            >
              <div className="glass-panel" style={{ 
                padding: '1rem 1.25rem', 
                borderLeft: milestone.completed ? '2px solid var(--status-secure)' : '1px solid var(--border-normal)',
                marginLeft: '0.5rem'
              }}>
                <div className="timeline-header">
                  <span className="timeline-quarter" style={{ color: milestone.completed ? 'var(--status-secure)' : 'var(--accent-cyan)' }}>
                    {milestone.quarter}
                  </span>
                  <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', cursor: 'pointer' }}>
                    <input 
                      type="checkbox" 
                      checked={milestone.completed} 
                      onChange={() => toggleMilestone(milestone.id)}
                      style={{ 
                        width: '16px', 
                        height: '16px', 
                        accentColor: 'var(--status-secure)',
                        cursor: 'pointer'
                      }}
                    />
                    <span style={{ fontSize: '0.8rem', color: milestone.completed ? 'var(--status-secure)' : 'var(--text-secondary)' }}>
                      {milestone.completed ? 'Completed' : 'Pending'}
                    </span>
                  </label>
                </div>
                <h4 className="timeline-title" style={{ 
                  color: milestone.completed ? 'var(--text-primary)' : 'var(--text-secondary)',
                  marginTop: '0.25rem'
                }}>
                  {milestone.title}
                </h4>
                <p className="timeline-desc" style={{ marginTop: '0.25rem' }}>
                  {milestone.description}
                </p>
              </div>
            </div>
          ))}
        </div>
      </div>
    </>
  );
};
