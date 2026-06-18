import type { NotificationMessage } from '../types/notification'

export interface FilterRule {
  type: 'whitelist' | 'blacklist'
  pattern: string
  enabled: boolean
}

export interface FilterResult {
  allowed: boolean
  matchedRule?: FilterRule
  reason?: string
}

function matchPattern(text: string, pattern: string): boolean {
  const regexStr = '^' + pattern
    .replace(/[.+^${}()|[\]\\]/g, '\\$&')
    .replace(/\*/g, '.*') + '$'
  return new RegExp(regexStr, 'i').test(text)
}

export class FilterEngine {
  private rules: FilterRule[] = []
  private defaultAllowed = true

  constructor(rules?: FilterRule[]) {
    if (rules) {
      this.loadRules(rules)
    }
  }

  loadRules(rules: FilterRule[]): void {
    this.rules = rules.slice()
  }

  shouldForward(pkgName: string, notification?: NotificationMessage): FilterResult {
    if (!pkgName) {
      return { allowed: this.defaultAllowed, reason: 'empty package name' }
    }

    const activeRules = this.rules.filter(r => r.enabled)

    if (activeRules.length === 0) {
      return { allowed: this.defaultAllowed, reason: 'no active rules' }
    }

    const whitelistRules = activeRules.filter(r => r.type === 'whitelist')
    const blacklistRules = activeRules.filter(r => r.type === 'blacklist')

    if (whitelistRules.length > 0) {
      const matched = whitelistRules.find(r => matchPattern(pkgName, r.pattern))
      if (!matched) {
        const reason = `package ${pkgName} not in whitelist`
        return { allowed: false, reason }
      }
      if (notification) {
        return this.checkContentFilter(matched, notification)
      }
      return { allowed: true, matchedRule: matched }
    }

    if (blacklistRules.length > 0) {
      const matched = blacklistRules.find(r => matchPattern(pkgName, r.pattern))
      if (matched) {
        return {
          allowed: false,
          matchedRule: matched,
          reason: `package ${pkgName} matched blacklist pattern ${matched.pattern}`,
        }
      }
      if (notification) {
        return this.checkContentFilter(blacklistRules[0], notification)
      }
      return { allowed: true }
    }

    return { allowed: this.defaultAllowed }
  }

  private checkContentFilter(rule: FilterRule, notification: NotificationMessage): FilterResult {
    const title = notification.title || ''
    const text = notification.text || ''

    if (rule.type === 'blacklist') {
      if (title.includes(rule.pattern) || text.includes(rule.pattern)) {
        return {
          allowed: false,
          matchedRule: rule,
          reason: `content matched blacklist pattern ${rule.pattern}`,
        }
      }
      return { allowed: true, matchedRule: rule }
    }

    return { allowed: true, matchedRule: rule }
  }

  addRule(rule: FilterRule): void {
    this.rules.push(rule)
  }

  removeRule(pattern: string): void {
    this.rules = this.rules.filter(r => r.pattern !== pattern)
  }

  getRules(): FilterRule[] {
    return this.rules.slice()
  }
}
