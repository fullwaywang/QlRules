/**
 * @name linux-181e448d8709e517c9c7b523fcd209f24eb38ca7-io_sq_thread
 * @id cpp/linux/181e448d8709e517c9c7b523fcd209f24eb38ca7/io-sq-thread
 * @description linux-181e448d8709e517c9c7b523fcd209f24eb38ca7-io_sq_thread 
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func) {
	exists(DeclStmt target_0 |
		target_0.getDeclarationEntry(0).(VariableDeclarationEntry).getType() instanceof PointerType
		and func.getEntryPoint().(BlockStmt).getStmt(2)=target_0)
}

predicate func_1(Variable vctx_3268, Function func) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(AssignExpr).getLValue().(VariableAccess).getType().hasName("const cred *")
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("override_creds")
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="creds"
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctx_3268
		and (func.getEntryPoint().(BlockStmt).getStmt(11)=target_1 or func.getEntryPoint().(BlockStmt).getStmt(11).getFollowingStmt()=target_1))
}

predicate func_2(Function func) {
	exists(ExprStmt target_2 |
		target_2.getExpr().(FunctionCall).getTarget().hasName("revert_creds")
		and target_2.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getType().hasName("const cred *")
		and (func.getEntryPoint().(BlockStmt).getStmt(17)=target_2 or func.getEntryPoint().(BlockStmt).getStmt(17).getFollowingStmt()=target_2))
}

predicate func_3(Variable vctx_3268) {
	exists(PointerFieldAccess target_3 |
		target_3.getTarget().getName()="completions"
		and target_3.getQualifier().(VariableAccess).getTarget()=vctx_3268)
}

from Function func, Variable vctx_3268
where
not func_0(func)
and not func_1(vctx_3268, func)
and not func_2(func)
and vctx_3268.getType().hasName("io_ring_ctx *")
and func_3(vctx_3268)
and vctx_3268.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
