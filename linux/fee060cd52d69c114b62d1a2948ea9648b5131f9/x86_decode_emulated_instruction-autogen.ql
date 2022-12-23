/**
 * @name linux-fee060cd52d69c114b62d1a2948ea9648b5131f9-x86_decode_emulated_instruction
 * @id cpp/linux/fee060cd52d69c114b62d1a2948ea9648b5131f9/x86-decode-emulated-instruction
 * @description linux-fee060cd52d69c114b62d1a2948ea9648b5131f9-x86_decode_emulated_instruction CVE-2022-1852
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vr_8373) {
	exists(ReturnStmt target_0 |
		target_0.getExpr().(VariableAccess).getTarget()=vr_8373
		and target_0.getParent().(IfStmt).getCondition() instanceof LogicalAndExpr)
}

predicate func_1(Function func) {
	exists(Initializer target_1 |
		target_1.getExpr().(Literal).getValue()="0"
		and target_1.getExpr().getEnclosingFunction() = func)
}

predicate func_2(Parameter vvcpu_8370, Parameter vemulation_type_8370, Variable vr_8373, Function func) {
	exists(IfStmt target_2 |
		target_2.getCondition().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(BitwiseAndExpr).getLeftOperand().(VariableAccess).getTarget()=vemulation_type_8370
		and target_2.getCondition().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(BitwiseAndExpr).getRightOperand().(BinaryBitwiseOperation).getLeftOperand().(Literal).getValue()="1"
		and target_2.getCondition().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(BitwiseAndExpr).getRightOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="2"
		and target_2.getCondition().(LogicalAndExpr).getAnOperand().(FunctionCall).getTarget().hasName("kvm_vcpu_check_breakpoint")
		and target_2.getCondition().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vvcpu_8370
		and target_2.getCondition().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vr_8373
		and target_2.getThen() instanceof ReturnStmt
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_2)
}

from Function func, Parameter vvcpu_8370, Parameter vemulation_type_8370, Variable vr_8373
where
func_0(vr_8373)
and func_1(func)
and func_2(vvcpu_8370, vemulation_type_8370, vr_8373, func)
and vvcpu_8370.getType().hasName("kvm_vcpu *")
and vemulation_type_8370.getType().hasName("int")
and vr_8373.getType().hasName("int")
and vvcpu_8370.getParentScope+() = func
and vemulation_type_8370.getParentScope+() = func
and vr_8373.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
