/**
 * @name linux-0f923e07124df069ba68d8bb12324398f4b6b709-nested_vmcb02_prepare_control
 * @id cpp/linux/0f923e07124df069ba68d8bb12324398f4b6b709/nested_vmcb02_prepare_control
 * @description linux-0f923e07124df069ba68d8bb12324398f4b6b709-nested_vmcb02_prepare_control CVE-2021-3653
 * @kind problem
 * @tags security
 */

import cpp

predicate func_6(Function func) {
	exists(VariableDeclarationEntry target_6 |
		target_6.getVariable().getInitializer().(Initializer).getExpr().(BitwiseOrExpr).getValue()="50332160"
		and target_6.getVariable().getInitializer().(Initializer).getExpr().(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getValue()="50331648"
		and target_6.getVariable().getInitializer().(Initializer).getExpr().(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getLeftOperand().(BinaryBitwiseOperation).getLeftOperand().(Literal).getValue()="1"
		and target_6.getVariable().getInitializer().(Initializer).getExpr().(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getLeftOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="24"
		and target_6.getVariable().getInitializer().(Initializer).getExpr().(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getRightOperand().(BinaryBitwiseOperation).getLeftOperand().(Literal).getValue()="1"
		and target_6.getVariable().getInitializer().(Initializer).getExpr().(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getRightOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="25"
		and target_6.getVariable().getInitializer().(Initializer).getExpr().(BitwiseOrExpr).getRightOperand().(BinaryBitwiseOperation).getValue()="512"
		and target_6.getVariable().getInitializer().(Initializer).getExpr().(BitwiseOrExpr).getRightOperand().(BinaryBitwiseOperation).getLeftOperand().(Literal).getValue()="1"
		and target_6.getVariable().getInitializer().(Initializer).getExpr().(BitwiseOrExpr).getRightOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="9"
		and target_6.getDeclaration().getParentScope+() = func)
}

predicate func_7(Variable vmask_506) {
	exists(VariableAccess target_7 |
		target_7.getTarget()=vmask_506)
}

predicate func_9(Function func) {
	exists(DeclStmt target_9 |
		target_9.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(BitwiseOrExpr).getValue()="2031887"
		and target_9.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(BitwiseOrExpr).getLeftOperand().(Literal).getValue()="15"
		and target_9.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(BitwiseOrExpr).getRightOperand().(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getLeftOperand().(BinaryBitwiseOperation).getLeftOperand().(Literal).getValue()="1"
		and target_9.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(BitwiseOrExpr).getRightOperand().(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getLeftOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="8"
		and target_9.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(BitwiseOrExpr).getRightOperand().(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getRightOperand().(BinaryBitwiseOperation).getLeftOperand().(Literal).getValue()="15"
		and target_9.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(BitwiseOrExpr).getRightOperand().(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getRightOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="16"
		and target_9.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(BitwiseOrExpr).getRightOperand().(BitwiseOrExpr).getRightOperand().(BinaryBitwiseOperation).getLeftOperand().(Literal).getValue()="1"
		and target_9.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(BitwiseOrExpr).getRightOperand().(BitwiseOrExpr).getRightOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="20"
		and func.getEntryPoint().(BlockStmt).getStmt(1)=target_9)
}

predicate func_12(Variable vmask_506) {
	exists(ComplementExpr target_12 |
		target_12.getValue()="4244635135"
		and target_12.getOperand().(VariableAccess).getTarget()=vmask_506)
}

from Function func, Variable vmask_506
where
func_6(func)
and func_7(vmask_506)
and not func_9(func)
and func_12(vmask_506)
and vmask_506.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
