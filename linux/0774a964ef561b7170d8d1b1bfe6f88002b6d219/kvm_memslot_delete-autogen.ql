/**
 * @name linux-0774a964ef561b7170d8d1b1bfe6f88002b6d219-kvm_memslot_delete
 * @id cpp/linux/0774a964ef561b7170d8d1b1bfe6f88002b6d219/kvm-memslot-delete
 * @description linux-0774a964ef561b7170d8d1b1bfe6f88002b6d219-kvm_memslot_delete 
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vslots_874, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(RelationalOperation).getGreaterOperand().(FunctionCall).getTarget().hasName("atomic_read")
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="lru_slot"
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vslots_874
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getTarget().getName()="used_slots"
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vslots_874
		and target_0.getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("atomic_set")
		and target_0.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="lru_slot"
		and target_0.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vslots_874
		and target_0.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and (func.getEntryPoint().(BlockStmt).getStmt(4)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(4).getFollowingStmt()=target_0))
}

predicate func_1(Parameter vslots_874) {
	exists(PointerFieldAccess target_1 |
		target_1.getTarget().getName()="used_slots"
		and target_1.getQualifier().(VariableAccess).getTarget()=vslots_874)
}

from Function func, Parameter vslots_874
where
not func_0(vslots_874, func)
and vslots_874.getType().hasName("kvm_memslots *")
and func_1(vslots_874)
and vslots_874.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
