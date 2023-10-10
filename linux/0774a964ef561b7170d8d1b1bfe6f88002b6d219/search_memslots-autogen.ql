/**
 * @name linux-0774a964ef561b7170d8d1b1bfe6f88002b6d219-search_memslots
 * @id cpp/linux/0774a964ef561b7170d8d1b1bfe6f88002b6d219/search-memslots
 * @description linux-0774a964ef561b7170d8d1b1bfe6f88002b6d219-search_memslots 
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vslots_1029, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(FunctionCall).getTarget().hasName("__builtin_expect")
		and target_0.getCondition().(FunctionCall).getArgument(0).(NotExpr).getOperand().(NotExpr).getOperand().(NotExpr).getOperand().(PointerFieldAccess).getTarget().getName()="used_slots"
		and target_0.getCondition().(FunctionCall).getArgument(0).(NotExpr).getOperand().(NotExpr).getOperand().(NotExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vslots_1029
		and target_0.getCondition().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and target_0.getThen() instanceof ReturnStmt
		and (func.getEntryPoint().(BlockStmt).getStmt(3)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(3).getFollowingStmt()=target_0))
}

predicate func_1(Function func) {
	exists(ReturnStmt target_1 |
		target_1.getExpr().(Literal).getValue()="0"
		and (func.getEntryPoint().(BlockStmt).getStmt(7)=target_1 or func.getEntryPoint().(BlockStmt).getStmt(7).getFollowingStmt()=target_1))
}

predicate func_3(Parameter vslots_1029) {
	exists(PointerFieldAccess target_3 |
		target_3.getTarget().getName()="memslots"
		and target_3.getQualifier().(VariableAccess).getTarget()=vslots_1029)
}

from Function func, Parameter vslots_1029
where
not func_0(vslots_1029, func)
and not func_1(func)
and vslots_1029.getType().hasName("kvm_memslots *")
and func_3(vslots_1029)
and vslots_1029.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
