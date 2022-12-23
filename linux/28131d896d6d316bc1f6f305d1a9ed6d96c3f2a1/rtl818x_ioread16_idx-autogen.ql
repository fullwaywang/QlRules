/**
 * @name linux-28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1-rtl818x_ioread16_idx
 * @id cpp/linux/28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1/rtl818x-ioread16-idx
 * @description linux-28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1-rtl818x_ioread16_idx CVE-2020-24588
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func) {
	exists(Literal target_0 |
		target_0.getValue()="250"
		and not target_0.getValue()="500"
		and target_0.getParent().(DivExpr).getParent().(FunctionCall).getArgument(8) instanceof DivExpr
		and target_0.getEnclosingFunction() = func)
}

predicate func_1(Parameter vpriv_39, Parameter vaddr_40, Parameter vidx_40, Variable vval_42) {
	exists(DivExpr target_1 |
		target_1.getValue()="125"
		and target_1.getLeftOperand() instanceof Literal
		and target_1.getRightOperand().(Literal).getValue()="2"
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("usb_control_msg")
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="udev"
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpriv_39
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getLeftOperand().(BinaryBitwiseOperation).getLeftOperand().(Literal).getValue()="2"
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getLeftOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="30"
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getRightOperand().(FunctionCall).getTarget().hasName("__create_pipe")
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getRightOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="udev"
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getRightOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpriv_39
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(BitwiseOrExpr).getLeftOperand().(BitwiseOrExpr).getRightOperand().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(BitwiseOrExpr).getRightOperand().(Literal).getValue()="128"
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(Literal).getValue()="5"
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(3).(Literal).getValue()="192"
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vaddr_40
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(5).(BitwiseAndExpr).getLeftOperand().(VariableAccess).getTarget()=vidx_40
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(5).(BitwiseAndExpr).getRightOperand().(HexLiteral).getValue()="3"
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(6).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="bits16"
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(6).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="io_dmabuf"
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(6).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpriv_39
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(7).(SizeofExprOperator).getValue()="2"
		and target_1.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(7).(SizeofExprOperator).getExprOperand().(VariableAccess).getTarget()=vval_42)
}

from Function func, Parameter vpriv_39, Parameter vaddr_40, Parameter vidx_40, Variable vval_42
where
func_0(func)
and func_1(vpriv_39, vaddr_40, vidx_40, vval_42)
and vpriv_39.getType().hasName("rtl8187_priv *")
and vaddr_40.getType().hasName("__le16 *")
and vidx_40.getType().hasName("u8")
and vval_42.getType().hasName("__le16")
and vpriv_39.getParentScope+() = func
and vaddr_40.getParentScope+() = func
and vidx_40.getParentScope+() = func
and vval_42.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
