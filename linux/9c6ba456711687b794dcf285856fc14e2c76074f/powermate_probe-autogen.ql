/**
 * @name linux-9c6ba456711687b794dcf285856fc14e2c76074f-powermate_probe
 * @id cpp/linux/9c6ba456711687b794dcf285856fc14e2c76074f/powermate_probe
 * @description linux-9c6ba456711687b794dcf285856fc14e2c76074f-powermate_probe 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Variable vinterface_302, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(RelationalOperation).getLesserOperand().(ValueFieldAccess).getTarget().getName()="bNumEndpoints"
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="desc"
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vinterface_302
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="1"
		and target_0.getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-22"
		and target_0.getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getOperand().(Literal).getValue()="22"
		and (func.getEntryPoint().(BlockStmt).getStmt(8)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(8).getFollowingStmt()=target_0))
}

predicate func_1(Variable vinterface_302, Parameter vintf_299) {
	exists(AssignExpr target_1 |
		target_1.getLValue().(VariableAccess).getTarget()=vinterface_302
		and target_1.getRValue().(PointerFieldAccess).getTarget().getName()="cur_altsetting"
		and target_1.getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vintf_299)
}

from Function func, Variable vinterface_302, Parameter vintf_299
where
not func_0(vinterface_302, func)
and vinterface_302.getType().hasName("usb_host_interface *")
and func_1(vinterface_302, vintf_299)
and vintf_299.getType().hasName("usb_interface *")
and vinterface_302.getParentScope+() = func
and vintf_299.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
