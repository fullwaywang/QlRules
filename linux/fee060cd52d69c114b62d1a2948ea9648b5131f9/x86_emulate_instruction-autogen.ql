/**
 * @name linux-fee060cd52d69c114b62d1a2948ea9648b5131f9-x86_emulate_instruction
 * @id cpp/linux/fee060cd52d69c114b62d1a2948ea9648b5131f9/x86-emulate-instruction
 * @description linux-fee060cd52d69c114b62d1a2948ea9648b5131f9-x86_emulate_instruction CVE-2022-1852
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vvcpu_8396, Parameter vemulation_type_8397, Variable vr_8399) {
	exists(IfStmt target_0 |
		target_0.getCondition().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(BitwiseAndExpr).getLeftOperand().(VariableAccess).getTarget()=vemulation_type_8397
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(BitwiseAndExpr).getRightOperand().(BinaryBitwiseOperation).getLeftOperand().(Literal).getValue()="1"
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(BitwiseAndExpr).getRightOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="2"
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(FunctionCall).getTarget().hasName("kvm_vcpu_check_code_breakpoint")
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vvcpu_8396
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vr_8399
		and target_0.getThen() instanceof ReturnStmt
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(NotExpr).getOperand().(BitwiseAndExpr).getLeftOperand().(VariableAccess).getTarget()=vemulation_type_8397
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(NotExpr).getOperand().(BitwiseAndExpr).getRightOperand().(BinaryBitwiseOperation).getLeftOperand().(Literal).getValue()="1"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(NotExpr).getOperand().(BitwiseAndExpr).getRightOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="0")
}

predicate func_2(Variable vr_8399, Function func) {
	exists(ReturnStmt target_2 |
		target_2.getExpr().(VariableAccess).getTarget()=vr_8399
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_2)
}

predicate func_3(Parameter vvcpu_8396) {
	exists(FunctionCall target_3 |
		target_3.getTarget().hasName("kvm_clear_exception_queue")
		and target_3.getArgument(0).(VariableAccess).getTarget()=vvcpu_8396)
}

predicate func_4(Parameter vvcpu_8396, Parameter vemulation_type_8397, Parameter vinsn_8397, Parameter vinsn_len_8397, Variable vr_8399) {
	exists(BitwiseAndExpr target_4 |
		target_4.getLeftOperand().(VariableAccess).getTarget()=vemulation_type_8397
		and target_4.getRightOperand().(BinaryBitwiseOperation).getValue()="1"
		and target_4.getRightOperand().(BinaryBitwiseOperation).getLeftOperand().(Literal).getValue()="1"
		and target_4.getRightOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="0"
		and target_4.getParent().(NotExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("kvm_clear_exception_queue")
		and target_4.getParent().(NotExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vvcpu_8396
		and target_4.getParent().(NotExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vr_8399
		and target_4.getParent().(NotExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("x86_decode_emulated_instruction")
		and target_4.getParent().(NotExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vvcpu_8396
		and target_4.getParent().(NotExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vemulation_type_8397
		and target_4.getParent().(NotExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vinsn_8397
		and target_4.getParent().(NotExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vinsn_len_8397
		and target_4.getParent().(NotExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(2).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vr_8399
		and target_4.getParent().(NotExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(2).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_4.getParent().(NotExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(BitwiseAndExpr).getLeftOperand().(VariableAccess).getTarget()=vemulation_type_8397
		and target_4.getParent().(NotExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(BitwiseAndExpr).getRightOperand().(BinaryBitwiseOperation).getLeftOperand().(Literal).getValue()="1"
		and target_4.getParent().(NotExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(BitwiseAndExpr).getRightOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="1"
		and target_4.getParent().(NotExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(BitwiseAndExpr).getLeftOperand().(VariableAccess).getTarget()=vemulation_type_8397
		and target_4.getParent().(NotExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(BitwiseAndExpr).getRightOperand().(BinaryBitwiseOperation).getLeftOperand().(Literal).getValue()="1"
		and target_4.getParent().(NotExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(LogicalOrExpr).getAnOperand().(BitwiseAndExpr).getRightOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="4"
		and target_4.getParent().(NotExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("kvm_queue_exception")
		and target_4.getParent().(NotExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vvcpu_8396
		and target_4.getParent().(NotExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="6"
		and target_4.getParent().(NotExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(Literal).getValue()="1")
}

predicate func_5(Parameter vvcpu_8396, Variable vr_8399) {
	exists(AssignExpr target_5 |
		target_5.getLValue().(VariableAccess).getTarget()=vr_8399
		and target_5.getRValue().(FunctionCall).getTarget().hasName("kvm_vcpu_do_singlestep")
		and target_5.getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vvcpu_8396)
}

from Function func, Parameter vvcpu_8396, Parameter vemulation_type_8397, Parameter vinsn_8397, Parameter vinsn_len_8397, Variable vr_8399
where
not func_0(vvcpu_8396, vemulation_type_8397, vr_8399)
and func_2(vr_8399, func)
and vvcpu_8396.getType().hasName("kvm_vcpu *")
and func_3(vvcpu_8396)
and vemulation_type_8397.getType().hasName("int")
and func_4(vvcpu_8396, vemulation_type_8397, vinsn_8397, vinsn_len_8397, vr_8399)
and vinsn_8397.getType().hasName("void *")
and vinsn_len_8397.getType().hasName("int")
and vr_8399.getType().hasName("int")
and func_5(vvcpu_8396, vr_8399)
and vvcpu_8396.getParentScope+() = func
and vemulation_type_8397.getParentScope+() = func
and vinsn_8397.getParentScope+() = func
and vinsn_len_8397.getParentScope+() = func
and vr_8399.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
