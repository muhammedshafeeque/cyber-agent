/**
 * Todo List Manager Service
 * Manages step-by-step penetration testing tasks
 */

const logger = require('../../cli/utils/logger');

class TodoManager {
  constructor() {
    this.todos = [];
    this.completed = [];
    this.currentTask = null;
    this.context = {}; // Shared context between tasks
  }

  /**
   * Add a new task
   */
  addTask(id, content, dependencies = []) {
    this.todos.push({
      id,
      content,
      status: 'pending',
      dependencies,
      startedAt: null,
      completedAt: null,
      result: null,
      context: {},
    });
    logger.info(`[TODO] Added task: ${content}`);
  }

  /**
   * Start a task
   */
  startTask(id) {
    const task = this.todos.find(t => t.id === id && t.status === 'pending');
    if (!task) {
      logger.warn(`[TODO] Task ${id} not found or not pending`);
      return false;
    }

    // Check dependencies
    const incompleteDeps = task.dependencies.filter(depId => {
      const dep = this.todos.find(t => t.id === depId);
      return !dep || dep.status !== 'completed';
    });

    if (incompleteDeps.length > 0) {
      logger.warn(`[TODO] Task ${id} has incomplete dependencies: ${incompleteDeps.join(', ')}`);
      return false;
    }

    task.status = 'in_progress';
    task.startedAt = new Date();
    this.currentTask = task;
    
    logger.step(`[TODO] Starting: ${task.content}`);
    return true;
  }

  /**
   * Complete a task with result
   */
  completeTask(id, result = null, context = {}) {
    const task = this.todos.find(t => t.id === id);
    if (!task) {
      logger.warn(`[TODO] Task ${id} not found`);
      return false;
    }

    task.status = 'completed';
    task.completedAt = new Date();
    task.result = result;
    task.context = { ...task.context, ...context };

    // Merge context into shared context
    this.context = { ...this.context, ...context };

    // Move to completed
    this.completed.push(task);
    this.todos = this.todos.filter(t => t.id !== id);

    if (this.currentTask?.id === id) {
      this.currentTask = null;
    }

    const success = result?.success !== false;
    logger.success(`[TODO] Completed: ${task.content} ${success ? '✓' : '✗'}`);
    
    if (result && !success && result.error) {
      logger.warn(`  Error: ${result.error}`);
    }

    return true;
  }

  /**
   * Get current task
   */
  getCurrentTask() {
    return this.currentTask;
  }

  /**
   * Get all pending tasks
   */
  getPendingTasks() {
    return this.todos.filter(t => t.status === 'pending');
  }

  /**
   * Get context
   */
  getContext(key = null) {
    if (key) {
      return this.context[key];
    }
    return this.context;
  }

  /**
   * Set context
   */
  setContext(key, value) {
    this.context[key] = value;
  }

  /**
   * Get summary
   */
  getSummary() {
    return {
      total: this.todos.length + this.completed.length,
      pending: this.todos.length,
      completed: this.completed.length,
      inProgress: this.currentTask ? 1 : 0,
    };
  }

  /**
   * Display status
   */
  displayStatus() {
    const summary = this.getSummary();
    logger.info(`[TODO] Status: ${summary.completed}/${summary.total} completed, ${summary.pending} pending`);
    
    if (this.currentTask) {
      logger.step(`[TODO] Current: ${this.currentTask.content}`);
    }
  }
}

module.exports = TodoManager;

