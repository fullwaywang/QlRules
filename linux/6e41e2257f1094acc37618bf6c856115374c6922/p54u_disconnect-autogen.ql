/**
 * @name linux-6e41e2257f1094acc37618bf6c856115374c6922-p54u_disconnect
 * @id cpp/linux/6e41e2257f1094acc37618bf6c856115374c6922/p54u_disconnect
 * @description linux-6e41e2257f1094acc37618bf6c856115374c6922-p54u_disconnect 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Parameter vintf_1063, Function func) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(FunctionCall).getTarget().hasName("usb_put_dev")
		and target_0.getExpr().(FunctionCall).getArgument(0).(FunctionCall).getTarget().hasName("interface_to_usbdev")
		and target_0.getExpr().(FunctionCall).getArgument(0).(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vintf_1063
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_0)
}

from Function func, Parameter vintf_1063
where
func_0(vintf_1063, func)
and vintf_1063.getType().hasName("usb_interface *")
and vintf_1063.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
