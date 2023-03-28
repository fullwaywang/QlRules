/**
 * @name redis-2a2a582e7cd99ba3b531336b8bd41df2b566e619-zrandmemberCommand
 * @id cpp/redis/2a2a582e7cd99ba3b531336b8bd41df2b566e619-zrandmembercommand
 * @description redis-2a2a582e7cd99ba3b531336b8bd41df2b566e619-zrandmemberCommand CVE-2023-25155
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vl_4286, Parameter vc_4285, FunctionCall target_0) {
		target_0.getTarget().hasName("getLongFromObjectOrReply")
		and not target_0.getTarget().hasName("getRangeLongFromObjectOrReply")
		and target_0.getArgument(0).(VariableAccess).getTarget()=vc_4285
		and target_0.getArgument(1).(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="argv"
		and target_0.getArgument(1).(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_4285
		and target_0.getArgument(1).(ArrayExpr).getArrayOffset().(Literal).getValue()="2"
		and target_0.getArgument(2).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vl_4286
		and target_0.getArgument(3).(Literal).getValue()="0"
		and target_0.getParent().(NEExpr).getAnOperand().(Literal).getValue()="0"
		and target_0.getParent().(NEExpr).getParent().(IfStmt).getThen() instanceof ReturnStmt
}

predicate func_1(Function func, DivExpr target_1) {
		target_1.getValue()="-4611686018427387904"
		and target_1.getEnclosingFunction() = func
}

predicate func_2(Function func, Literal target_2) {
		target_2.getValue()="1"
		and not target_2.getValue()="9223372036854775807"
		and target_2.getParent().(SubExpr).getParent().(DivExpr).getLeftOperand().(SubExpr).getValue()="-9223372036854775808"
		and target_2.getEnclosingFunction() = func
}

predicate func_4(Function func, UnaryMinusExpr target_4) {
		target_4.getValue()="-9223372036854775807"
		and target_4.getEnclosingFunction() = func
}

from Function func, Variable vl_4286, Parameter vc_4285, FunctionCall target_0, DivExpr target_1, Literal target_2, UnaryMinusExpr target_4
where
func_0(vl_4286, vc_4285, target_0)
and func_1(func, target_1)
and func_2(func, target_2)
and func_4(func, target_4)
and vl_4286.getType().hasName("long")
and vc_4285.getType().hasName("client *")
and vl_4286.getParentScope+() = func
and vc_4285.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
