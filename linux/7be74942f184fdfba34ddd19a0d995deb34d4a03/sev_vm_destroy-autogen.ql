/**
 * @name linux-7be74942f184fdfba34ddd19a0d995deb34d4a03-sev_vm_destroy
 * @id cpp/linux/7be74942f184fdfba34ddd19a0d995deb34d4a03/sev_vm_destroy
 * @description linux-7be74942f184fdfba34ddd19a0d995deb34d4a03-sev_vm_destroy 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Function func) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("___might_sleep")
		and target_0.getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0) instanceof StringLiteral
		and target_0.getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1) instanceof Literal
		and target_0.getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2) instanceof Literal
		and target_0.getExpr().(StmtExpr).getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("_cond_resched")
		and target_0.getEnclosingFunction() = func)
}

from Function func
where
not func_0(func)
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
