/**
 * @name linux-4491001c2e0fa69efbb748c96ec96b100a5cdb7e-talk_to_netback
 * @id cpp/linux/4491001c2e0fa69efbb748c96ec96b100a5cdb7e/talk_to_netback
 * @description linux-4491001c2e0fa69efbb748c96ec96b100a5cdb7e-talk_to_netback CVE-2022-33741
 * @kind problem
 * @tags security
 */

import cpp

predicate func_1(Variable vmax_queues_2211) {
	exists(VariableDeclarationEntry target_1 |
		target_1.getVariable().getInitializer().(Initializer).getExpr().(VariableAccess).getTarget()=vmax_queues_2211)
}

predicate func_3(Variable vxennet_max_queues) {
	exists(VariableDeclarationEntry target_3 |
		target_3.getVariable().getInitializer().(Initializer).getExpr().(VariableAccess).getTarget()=vxennet_max_queues)
}

predicate func_8(Parameter vinfo_2204, Parameter vdev_2203, Function func) {
	exists(ExprStmt target_8 |
		target_8.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="bounce"
		and target_8.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vinfo_2204
		and target_8.getExpr().(AssignExpr).getRValue().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(VariableAccess).getType().hasName("bool")
		and target_8.getExpr().(AssignExpr).getRValue().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("xenbus_read_unsigned")
		and target_8.getExpr().(AssignExpr).getRValue().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="nodename"
		and target_8.getExpr().(AssignExpr).getRValue().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdev_2203
		and target_8.getExpr().(AssignExpr).getRValue().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(1).(StringLiteral).getValue()="trusted"
		and target_8.getExpr().(AssignExpr).getRValue().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(2).(Literal).getValue()="1"
		and func.getEntryPoint().(BlockStmt).getStmt(10)=target_8)
}

predicate func_9(Parameter vinfo_2204) {
	exists(PointerFieldAccess target_9 |
		target_9.getTarget().getName()="netdev"
		and target_9.getQualifier().(VariableAccess).getTarget()=vinfo_2204)
}

from Function func, Parameter vinfo_2204, Parameter vdev_2203, Variable vmax_queues_2211, Variable vxennet_max_queues, Variable v__UNIQUE_ID___x1826_2221, Variable v__UNIQUE_ID___y1827_2221
where
func_1(vmax_queues_2211)
and func_3(vxennet_max_queues)
and not func_8(vinfo_2204, vdev_2203, func)
and vinfo_2204.getType().hasName("netfront_info *")
and func_9(vinfo_2204)
and vdev_2203.getType().hasName("xenbus_device *")
and vmax_queues_2211.getType().hasName("unsigned int")
and vxennet_max_queues.getType().hasName("unsigned int")
and vinfo_2204.getParentScope+() = func
and vdev_2203.getParentScope+() = func
and vmax_queues_2211.getParentScope+() = func
and not vxennet_max_queues.getParentScope+() = func
and v__UNIQUE_ID___x1826_2221.getParentScope+() = func
and v__UNIQUE_ID___y1827_2221.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
