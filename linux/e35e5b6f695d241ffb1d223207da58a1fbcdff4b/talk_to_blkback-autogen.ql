/**
 * @name linux-e35e5b6f695d241ffb1d223207da58a1fbcdff4b-talk_to_blkback
 * @id cpp/linux/e35e5b6f695d241ffb1d223207da58a1fbcdff4b/talk-to-blkback
 * @description linux-e35e5b6f695d241ffb1d223207da58a1fbcdff4b-talk_to_blkback CVE-2022-26365
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_1(Variable vxen_blkif_max_ring_order) {
	exists(VariableDeclarationEntry target_1 |
		target_1.getVariable().getInitializer().(Initializer).getExpr().(VariableAccess).getTarget()=vxen_blkif_max_ring_order)
}

predicate func_3(Variable vmax_page_order_1760) {
	exists(VariableDeclarationEntry target_3 |
		target_3.getVariable().getInitializer().(Initializer).getExpr().(VariableAccess).getTarget()=vmax_page_order_1760)
}

predicate func_8(Parameter vinfo_1755, Parameter vdev_1754, Function func) {
	exists(ExprStmt target_8 |
		target_8.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="bounce"
		and target_8.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vinfo_1755
		and target_8.getExpr().(AssignExpr).getRValue().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(VariableAccess).getType().hasName("bool")
		and target_8.getExpr().(AssignExpr).getRValue().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("xenbus_read_unsigned")
		and target_8.getExpr().(AssignExpr).getRValue().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="nodename"
		and target_8.getExpr().(AssignExpr).getRValue().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdev_1754
		and target_8.getExpr().(AssignExpr).getRValue().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(1).(StringLiteral).getValue()="trusted"
		and target_8.getExpr().(AssignExpr).getRValue().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(2).(Literal).getValue()="1"
		and (func.getEntryPoint().(BlockStmt).getStmt(7)=target_8 or func.getEntryPoint().(BlockStmt).getStmt(7).getFollowingStmt()=target_8))
}

predicate func_9(Parameter vinfo_1755) {
	exists(NotExpr target_9 |
		target_9.getOperand().(VariableAccess).getTarget()=vinfo_1755
		and target_9.getParent().(IfStmt).getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-19"
		and target_9.getParent().(IfStmt).getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getOperand().(Literal).getValue()="19")
}

from Function func, Variable vmax_page_order_1760, Variable vxen_blkif_max_ring_order, Variable v__UNIQUE_ID___x1194_1769, Variable v__UNIQUE_ID___y1195_1769, Parameter vinfo_1755, Parameter vdev_1754
where
func_1(vxen_blkif_max_ring_order)
and func_3(vmax_page_order_1760)
and not func_8(vinfo_1755, vdev_1754, func)
and vmax_page_order_1760.getType().hasName("unsigned int")
and vxen_blkif_max_ring_order.getType().hasName("unsigned int")
and vinfo_1755.getType().hasName("blkfront_info *")
and func_9(vinfo_1755)
and vdev_1754.getType().hasName("xenbus_device *")
and vmax_page_order_1760.getParentScope+() = func
and not vxen_blkif_max_ring_order.getParentScope+() = func
and v__UNIQUE_ID___x1194_1769.getParentScope+() = func
and v__UNIQUE_ID___y1195_1769.getParentScope+() = func
and vinfo_1755.getParentScope+() = func
and vdev_1754.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
