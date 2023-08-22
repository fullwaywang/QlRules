/**
 * @name redis-2a2a582e7cd99ba3b531336b8bd41df2b566e619-srandmemberWithCountCommand
 * @id cpp/redis/2a2a582e7cd99ba3b531336b8bd41df2b566e619/srandmemberWithCountCommand
 * @description redis-2a2a582e7cd99ba3b531336b8bd41df2b566e619-src/t_set.c-srandmemberWithCountCommand CVE-2023-25155
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vl_658, Parameter vc_657, FunctionCall target_0) {
		target_0.getTarget().hasName("getLongFromObjectOrReply")
		and not target_0.getTarget().hasName("getRangeLongFromObjectOrReply")
		and target_0.getArgument(0).(VariableAccess).getTarget()=vc_657
		and target_0.getArgument(1).(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="argv"
		and target_0.getArgument(1).(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vc_657
		and target_0.getArgument(1).(ArrayExpr).getArrayOffset().(Literal).getValue()="2"
		and target_0.getArgument(2).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vl_658
		and target_0.getArgument(3).(Literal).getValue()="0"
		and target_0.getParent().(NEExpr).getAnOperand().(Literal).getValue()="0"
		and target_0.getParent().(NEExpr).getParent().(IfStmt).getThen() instanceof ReturnStmt
}

predicate func_1(Function func) {
	exists(UnaryMinusExpr target_1 |
		target_1.getValue()="-9223372036854775807"
		and target_1.getParent().(FunctionCall).getParent().(NEExpr).getAnOperand() instanceof FunctionCall
		and target_1.getEnclosingFunction() = func)
}

from Function func, Variable vl_658, Parameter vc_657, FunctionCall target_0
where
func_0(vl_658, vc_657, target_0)
and not func_1(func)
and vl_658.getType().hasName("long")
and vc_657.getType().hasName("client *")
and vl_658.(LocalVariable).getFunction() = func
and vc_657.getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
