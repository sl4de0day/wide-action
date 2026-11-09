export class Criterion {
  public readonly weight: number;
  public readonly term: (candidate: number) => number;

  constructor(weight: number, term: (candidate: number) => number) {
    if (weight < 0.0) throw new RangeError("weight cannot be negative");
    if (!term) throw new TypeError("term cannot be null");
    this.weight = weight;
    this.term = term;
  }
}

export class WeightedScorer {
  private readonly criteria: Criterion[];
  private readonly totalWeight: number;

  constructor(...criteria: Criterion[]) {
    if (!criteria || criteria.length === 0) throw new TypeError("criteria cannot be null or empty");
    this.criteria = [...criteria];
    let m = 0.0;
    for (const c of this.criteria) {
      if (!c || !c.term) throw new TypeError("criterion or term cannot be null");
      m += c.weight;
    }
    if (m <= 0.0) throw new RangeError("total weight must be positive");
    this.totalWeight = m;
  }

  public score(candidate: number): number {
    let s = 0.0;
    for (const c of this.criteria) {
      let f = c.term(candidate);
      if (f < 0.0) f = 0.0;
      else if (f > 1.0) f = 1.0;
      s += c.weight * f;
    }
    return s / this.totalWeight;
  }

  public trySelect(candidateCount: number, threshold = 0.5, bias = 1.0): { success: boolean; best: number; score: number } {
    if (candidateCount < 1 || bias <= 0.0) return { success: false, best: -1, score: 0.0 };

    const effectiveThreshold = threshold / bias;
    let bestIndex = -1;
    let bestScore = -1.0;

    for (let i = 0; i < candidateCount; i++) {
      const s = this.score(i);
      if (s > bestScore) {
        bestScore = s;
        bestIndex = i;
      }
    }

    if (bestScore >= effectiveThreshold && bestIndex >= 0) {
      return { success: true, best: bestIndex, score: bestScore };
    }

    return { success: false, best: bestIndex, score: bestScore };
  }
}

export class Commitment {
  private readonly lifetime: number;
  private readonly lockWindow: number;
  private adoptedAt: number;
  private currentScore: number;
  private hasCommitment: boolean;

  constructor(lifetime: number, lockWindow: number) {
    if (lifetime <= 0.0) throw new RangeError("lifetime must be positive");
    if (lockWindow < 0.0) throw new RangeError("lockWindow cannot be negative");

    this.lifetime = lifetime;
    this.lockWindow = lockWindow;
    this.adoptedAt = -Infinity;
    this.currentScore = 0.0;
    this.hasCommitment = false;
  }

  public get score(): number {
    return this.currentScore;
  }

  public get committed(): boolean {
    return this.hasCommitment;
  }

  public isExpired(now: number): boolean {
    return !this.hasCommitment || now - this.adoptedAt >= this.lifetime;
  }

  public isLocked(now: number): boolean {
    return this.hasCommitment && now - this.adoptedAt < this.lockWindow;
  }

  public shouldReplace(challengerScore: number, margin: number, now: number): boolean {
    if (this.isExpired(now)) return true;
    if (this.isLocked(now)) return false;
    return challengerScore >= this.currentScore + margin;
  }

  public adopt(score: number, now: number): void {
    this.currentScore = score;
    this.adoptedAt = now;
    this.hasCommitment = true;
  }
}
