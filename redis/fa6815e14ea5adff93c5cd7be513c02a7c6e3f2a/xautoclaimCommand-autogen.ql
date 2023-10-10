/**
 * @name redis-fa6815e14ea5adff93c5cd7be513c02a7c6e3f2a-xautoclaimCommand
 * @id cpp/redis/fa6815e14ea5adff93c5cd7be513c02a7c6e3f2a/xautoclaimCommand
 * @description redis-fa6815e14ea5adff93c5cd7be513c02a7c6e3f2a-src/t_stream.c-xautoclaimCommand CVE-2022-35951
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

predicate func_2(Parameter vc_3332, Variable vdeleted_ids_3402, ArrayExpr target_6, ExprStmt target_7, Function func) {
	exists(IfStmt target_2 |
		target_2.getCondition().(NotExpr).getOperand().(VariableAccess).getTarget()=vdeleted_ids_3402
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("addReplyError")
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vc_3332
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="Insufficient memory, failed allocating transient memory, COUNT too high."
		and (func.getEntryPoint().(BlockStmt).getStmt(17)=target_2 or func.getEntryPoint().(BlockStmt).getStmt(17).getFollowingStmt()=target_2)
		and target_6.getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_7.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_6(Parameter vc_3332, ArrayExpr target_6) {
		target_6.getArrayBase().(PointerFieldAccess).getTarget().getName()="argv"
		and target_6.getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_3332
		and target_6.getArrayOffset().(Literal).getValue()="2"
}

predicate func_7(Parameter vc_3332, ExprStmt target_7) {
		target_7.getExpr().(FunctionCall).getTarget().hasName("addReplyArrayLen")
		and target_7.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vc_3332
		and target_7.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="3"
}

from Function func, Variable vcount_3336, Parameter vc_3332, Variable vdeleted_ids_3402, FunctionCall target_0, ArrayExpr target_6, ExprStmt target_7
where
func_0(vcount_3336, target_0)
and not func_2(vc_3332, vdeleted_ids_3402, target_6, target_7, func)
and func_6(vc_3332, target_6)
and func_7(vc_3332, target_7)
and vcount_3336.getType().hasName("long")
and vc_3332.getType().hasName("client *")
and vdeleted_ids_3402.getType().hasName("streamID *")
and vcount_3336.(LocalVariable).getFunction() = func
and vc_3332.getFunction() = func
and vdeleted_ids_3402.(LocalVariable).getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
