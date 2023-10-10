/**
 * @name linux-6e41e2257f1094acc37618bf6c856115374c6922-p54u_load_firmware_cb
 * @id cpp/linux/6e41e2257f1094acc37618bf6c856115374c6922/p54u_load_firmware_cb
 * @description linux-6e41e2257f1094acc37618bf6c856115374c6922-p54u_load_firmware_cb 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Function func) {
	exists(FunctionCall target_0 |
		target_0.getTarget().hasName("device_release_driver")
		and not target_0.getTarget().hasName("device_lock")
		and target_0.getArgument(0) instanceof AddressOfExpr
		and target_0.getEnclosingFunction() = func)
}

predicate func_1(Function func) {
	exists(Initializer target_1 |
		target_1.getExpr().(ValueFieldAccess).getTarget().getName()="parent"
		and target_1.getExpr().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="dev"
		and target_1.getExpr().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier() instanceof PointerFieldAccess
		and target_1.getExpr().getEnclosingFunction() = func)
}

predicate func_2(Variable vparent_936) {
	exists(FunctionCall target_2 |
		target_2.getTarget().hasName("device_lock")
		and not target_2.getTarget().hasName("usb_driver_release_interface")
		and target_2.getArgument(0).(VariableAccess).getTarget()=vparent_936)
}

predicate func_3(Variable vudev_923) {
	exists(FunctionCall target_3 |
		target_3.getTarget().hasName("usb_put_dev")
		and not target_3.getTarget().hasName("usb_put_intf")
		and target_3.getArgument(0).(VariableAccess).getTarget()=vudev_923)
}

predicate func_4(Variable vpriv_922) {
	exists(VariableDeclarationEntry target_4 |
		target_4.getVariable().getInitializer().(Initializer).getExpr().(PointerFieldAccess).getTarget().getName()="intf"
		and target_4.getVariable().getInitializer().(Initializer).getExpr().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpriv_922)
}

predicate func_6(Variable verr_924) {
	exists(AddressOfExpr target_6 |
		target_6.getOperand().(PointerFieldAccess).getTarget().getName()="dev"
		and target_6.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getType().hasName("usb_interface *")
		and target_6.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("_dev_err")
		and target_6.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="failed to initialize device (%d)\n"
		and target_6.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=verr_924)
}

predicate func_8(Function func) {
	exists(AddressOfExpr target_8 |
		target_8.getOperand().(VariableAccess).getType().hasName("usb_driver")
		and target_8.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("usb_driver_release_interface")
		and target_8.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getType().hasName("usb_interface *")
		and target_8.getEnclosingFunction() = func)
}

predicate func_11(Variable vudev_923, Variable verr_924) {
	exists(AddressOfExpr target_11 |
		target_11.getOperand().(PointerFieldAccess).getTarget().getName()="dev"
		and target_11.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vudev_923
		and target_11.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("_dev_err")
		and target_11.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="failed to initialize device (%d)\n"
		and target_11.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=verr_924)
}

predicate func_13(Variable vpriv_922, Variable verr_924) {
	exists(ExprStmt target_13 |
		target_13.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vpriv_922
		and target_13.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_13.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(VariableAccess).getTarget()=verr_924)
}

predicate func_15(Function func) {
	exists(VariableDeclarationEntry target_15 |
		target_15.getVariable().getInitializer() instanceof Initializer
		and target_15.getDeclaration().getParentScope+() = func)
}

predicate func_16(Variable vpriv_922) {
	exists(PointerFieldAccess target_16 |
		target_16.getTarget().getName()="udev"
		and target_16.getQualifier().(VariableAccess).getTarget()=vpriv_922)
}

predicate func_17(Variable verr_924, Variable vparent_936) {
	exists(IfStmt target_17 |
		target_17.getCondition().(VariableAccess).getTarget()=vparent_936
		and target_17.getThen().(ExprStmt).getExpr() instanceof FunctionCall
		and target_17.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(VariableAccess).getTarget()=verr_924)
}

predicate func_18(Variable verr_924, Variable vparent_936) {
	exists(IfStmt target_18 |
		target_18.getCondition().(VariableAccess).getTarget()=vparent_936
		and target_18.getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("device_unlock")
		and target_18.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vparent_936
		and target_18.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(VariableAccess).getTarget()=verr_924)
}

from Function func, Variable vpriv_922, Variable vudev_923, Variable verr_924, Variable vparent_936
where
func_0(func)
and func_1(func)
and func_2(vparent_936)
and func_3(vudev_923)
and not func_4(vpriv_922)
and not func_6(verr_924)
and not func_8(func)
and func_11(vudev_923, verr_924)
and func_13(vpriv_922, verr_924)
and func_15(func)
and func_16(vpriv_922)
and func_17(verr_924, vparent_936)
and func_18(verr_924, vparent_936)
and vpriv_922.getType().hasName("p54u_priv *")
and vudev_923.getType().hasName("usb_device *")
and verr_924.getType().hasName("int")
and vpriv_922.getParentScope+() = func
and vudev_923.getParentScope+() = func
and verr_924.getParentScope+() = func
and vparent_936.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
