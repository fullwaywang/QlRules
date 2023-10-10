/**
 * @name linux-07d86ca93db7e5cdf4743564d98292042ec21af7-snd_usbmidi_create
 * @id cpp/linux/07d86ca93db7e5cdf4743564d98292042ec21af7/snd_usbmidi_create
 * @description linux-07d86ca93db7e5cdf4743564d98292042ec21af7-snd_usbmidi_create 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Variable vumidi_2328, Variable verr_2331) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(FunctionCall).getTarget().hasName("snd_usbmidi_free")
		and target_0.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vumidi_2328
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=verr_2331
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="0")
}

from Function func, Variable vumidi_2328, Variable verr_2331
where
func_0(vumidi_2328, verr_2331)
and vumidi_2328.getType().hasName("snd_usb_midi *")
and verr_2331.getType().hasName("int")
and vumidi_2328.getParentScope+() = func
and verr_2331.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
