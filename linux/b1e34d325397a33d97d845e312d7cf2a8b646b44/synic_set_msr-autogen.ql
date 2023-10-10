/**
 * @name linux-b1e34d325397a33d97d845e312d7cf2a8b646b44-synic_set_msr
 * @id cpp/linux/b1e34d325397a33d97d845e312d7cf2a8b646b44/synic_set_msr
 * @description linux-b1e34d325397a33d97d845e312d7cf2a8b646b44-synic_set_msr 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Parameter vsynic_236, Parameter vdata_237) {
	exists(LogicalOrExpr target_0 |
		target_0.getAnOperand() instanceof NotExpr
		and target_0.getAnOperand().(VariableAccess).getTarget()=vdata_237
		and target_0.getParent().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(PointerFieldAccess).getTarget().getName()="active"
		and target_0.getParent().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsynic_236
		and target_0.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen().(ReturnStmt).getExpr().(Literal).getValue()="1")
}

predicate func_1(Parameter vsynic_236) {
	exists(IfStmt target_1 |
		target_1.getCondition().(NotExpr).getOperand().(PointerFieldAccess).getTarget().getName()="active"
		and target_1.getCondition().(NotExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsynic_236
		and target_1.getThen().(BreakStmt).toString() = "break;")
}

predicate func_2(Parameter vsynic_236, Parameter vhost_237) {
	exists(NotExpr target_2 |
		target_2.getOperand().(VariableAccess).getTarget()=vhost_237
		and target_2.getParent().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(PointerFieldAccess).getTarget().getName()="active"
		and target_2.getParent().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsynic_236
		and target_2.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen().(ReturnStmt).getExpr().(Literal).getValue()="1")
}

predicate func_3(Parameter vsynic_236, Parameter vmsr_237) {
	exists(FunctionCall target_3 |
		target_3.getTarget().hasName("synic_exit")
		and target_3.getArgument(0).(VariableAccess).getTarget()=vsynic_236
		and target_3.getArgument(1).(VariableAccess).getTarget()=vmsr_237)
}

from Function func, Parameter vsynic_236, Parameter vmsr_237, Parameter vdata_237, Parameter vhost_237
where
not func_0(vsynic_236, vdata_237)
and not func_1(vsynic_236)
and func_2(vsynic_236, vhost_237)
and vsynic_236.getType().hasName("kvm_vcpu_hv_synic *")
and func_3(vsynic_236, vmsr_237)
and vmsr_237.getType().hasName("u32")
and vdata_237.getType().hasName("u64")
and vhost_237.getType().hasName("bool")
and vsynic_236.getParentScope+() = func
and vmsr_237.getParentScope+() = func
and vdata_237.getParentScope+() = func
and vhost_237.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
