/**
 * @name linux-a246b4d547708f33ff4d4b9a7a5dbac741dc89d8-cit_get_packet_size
 * @id cpp/linux/a246b4d547708f33ff4d4b9a7a5dbac741dc89d8/cit-get-packet-size
 * @description linux-a246b4d547708f33ff4d4b9a7a5dbac741dc89d8-cit_get_packet_size 
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable valt_1435, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(RelationalOperation).getLesserOperand().(ValueFieldAccess).getTarget().getName()="bNumEndpoints"
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="desc"
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=valt_1435
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="1"
		and target_0.getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-19"
		and target_0.getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getOperand().(Literal).getValue()="19"
		and (func.getEntryPoint().(BlockStmt).getStmt(5)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(5).getFollowingStmt()=target_0))
}

predicate func_1(Variable valt_1435) {
	exists(NotExpr target_1 |
		target_1.getOperand().(VariableAccess).getTarget()=valt_1435
		and target_1.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("printk")
		and target_1.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(StringLiteral).getValue()="3gspca_xirlink_cit: Couldn't get altsetting\n"
		and target_1.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(UnaryMinusExpr).getOperand().(Literal).getValue()="5")
}

from Function func, Variable valt_1435
where
not func_0(valt_1435, func)
and valt_1435.getType().hasName("usb_host_interface *")
and func_1(valt_1435)
and valt_1435.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
