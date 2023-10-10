/**
 * @name linux-a58d9166a756a0f4a6618e4f593232593d6df134-nested_svm_vmrun
 * @id cpp/linux/a58d9166a756a0f4a6618e4f593232593d6df134/nested-svm-vmrun
 * @description linux-a58d9166a756a0f4a6618e4f593232593d6df134-nested_svm_vmrun CVE-2021-29657
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vvmcb12_460, Parameter vsvm_457) {
	exists(FunctionCall target_0 |
		target_0.getTarget().hasName("nested_vmcb_checks")
		and not target_0.getTarget().hasName("nested_vmcb_check_save")
		and target_0.getArgument(0).(VariableAccess).getTarget()=vsvm_457
		and target_0.getArgument(1).(VariableAccess).getTarget()=vvmcb12_460)
}

predicate func_1(Variable vvmcb12_460, Parameter vsvm_457, Function func) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(FunctionCall).getTarget().hasName("load_nested_vmcb_control")
		and target_1.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsvm_457
		and target_1.getExpr().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="control"
		and target_1.getExpr().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vvmcb12_460
		and (func.getEntryPoint().(BlockStmt).getStmt(13)=target_1 or func.getEntryPoint().(BlockStmt).getStmt(13).getFollowingStmt()=target_1))
}

predicate func_2(Variable vvmcb12_460, Parameter vsvm_457) {
	exists(LogicalOrExpr target_2 |
		target_2.getAnOperand().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("nested_vmcb_check_save")
		and target_2.getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsvm_457
		and target_2.getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vvmcb12_460
		and target_2.getAnOperand().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("nested_vmcb_check_controls")
		and target_2.getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(ValueFieldAccess).getTarget().getName()="ctl"
		and target_2.getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="nested"
		and target_2.getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vsvm_457
		and target_2.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="exit_code"
		and target_2.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="control"
		and target_2.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vvmcb12_460
		and target_2.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(UnaryMinusExpr).getOperand().(Literal).getValue()="1"
		and target_2.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="exit_code_hi"
		and target_2.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="control"
		and target_2.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vvmcb12_460
		and target_2.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_2.getParent().(IfStmt).getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="exit_info_1"
		and target_2.getParent().(IfStmt).getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="control"
		and target_2.getParent().(IfStmt).getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vvmcb12_460
		and target_2.getParent().(IfStmt).getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0")
}

predicate func_3(Variable vvmcb12_460, Variable vmap_463) {
	exists(AssignExpr target_3 |
		target_3.getLValue().(VariableAccess).getTarget()=vvmcb12_460
		and target_3.getRValue().(ValueFieldAccess).getTarget().getName()="hva"
		and target_3.getRValue().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vmap_463)
}

predicate func_4(Parameter vsvm_457) {
	exists(PointerFieldAccess target_4 |
		target_4.getTarget().getName()="nested"
		and target_4.getQualifier().(VariableAccess).getTarget()=vsvm_457)
}

from Function func, Variable vvmcb12_460, Variable vmap_463, Parameter vsvm_457
where
func_0(vvmcb12_460, vsvm_457)
and not func_1(vvmcb12_460, vsvm_457, func)
and not func_2(vvmcb12_460, vsvm_457)
and vvmcb12_460.getType().hasName("vmcb *")
and func_3(vvmcb12_460, vmap_463)
and vmap_463.getType().hasName("kvm_host_map")
and vsvm_457.getType().hasName("vcpu_svm *")
and func_4(vsvm_457)
and vvmcb12_460.getParentScope+() = func
and vmap_463.getParentScope+() = func
and vsvm_457.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
