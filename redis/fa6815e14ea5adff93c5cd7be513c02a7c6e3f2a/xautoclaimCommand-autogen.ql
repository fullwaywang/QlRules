/**
 * @name redis-fa6815e14ea5adff93c5cd7be513c02a7c6e3f2a-xautoclaimCommand
 * @id cpp/redis/fa6815e14ea5adff93c5cd7be513c02a7c6e3f2a/xautoclaimCommand
 * @description redis-fa6815e14ea5adff93c5cd7be513c02a7c6e3f2a-xautoclaimCommand CVE-2022-35951
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vcount_3336, FunctionCall target_0) {
		target_0.getTarget().hasName("zmalloc")
		and not target_0.getTarget().hasName("ztrymalloc")
		and target_0.getArgument(0).(MulExpr).getLeftOperand().(VariableAccess).getTarget()=vcount_3336
		and target_0.getArgument(0).(MulExpr).getRightOperand().(SizeofTypeOperator).getType() instanceof LongType
		and target_0.getArgument(0).(MulExpr).getRightOperand().(SizeofTypeOperator).getValue()="16"
}

predicate func_3(Parameter vc_3332, Variable vdeleted_ids_3402, ArrayExpr target_9, ExprStmt target_10, Function func) {
	exists(IfStmt target_3 |
		target_3.getCondition().(NotExpr).getOperand().(VariableAccess).getTarget()=vdeleted_ids_3402
		and target_3.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("addReplyError")
		and target_3.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vc_3332
		and target_3.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="Insufficient memory, failed allocating transient memory, COUNT too high."
		and target_3.getThen().(BlockStmt).getStmt(1) instanceof ReturnStmt
		and (func.getEntryPoint().(BlockStmt).getStmt(17)=target_3 or func.getEntryPoint().(BlockStmt).getStmt(17).getFollowingStmt()=target_3)
		and target_9.getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_3.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_3.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_10.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_6(Function func, ReturnStmt target_6) {
		target_6.toString() = "return ..."
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_6
}

predicate func_9(Parameter vc_3332, ArrayExpr target_9) {
		target_9.getArrayBase().(PointerFieldAccess).getTarget().getName()="argv"
		and target_9.getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_3332
		and target_9.getArrayOffset().(Literal).getValue()="2"
}

predicate func_10(Parameter vc_3332, ExprStmt target_10) {
		target_10.getExpr().(FunctionCall).getTarget().hasName("addReplyArrayLen")
		and target_10.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vc_3332
		and target_10.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="3"
}

from Function func, Parameter vc_3332, Variable vcount_3336, Variable vdeleted_ids_3402, FunctionCall target_0, ReturnStmt target_6, ArrayExpr target_9, ExprStmt target_10
where
func_0(vcount_3336, target_0)
and not func_3(vc_3332, vdeleted_ids_3402, target_9, target_10, func)
and func_6(func, target_6)
and func_9(vc_3332, target_9)
and func_10(vc_3332, target_10)
and vc_3332.getType().hasName("client *")
and vcount_3336.getType().hasName("long")
and vdeleted_ids_3402.getType().hasName("streamID *")
and vc_3332.getParentScope+() = func
and vcount_3336.getParentScope+() = func
and vdeleted_ids_3402.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
