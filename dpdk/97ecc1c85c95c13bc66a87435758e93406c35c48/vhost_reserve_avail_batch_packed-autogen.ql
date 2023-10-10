/**
 * @name dpdk-97ecc1c85c95c13bc66a87435758e93406c35c48-vhost_reserve_avail_batch_packed
 * @id cpp/dpdk/97ecc1c85c95c13bc66a87435758e93406c35c48/vhost-reserve-avail-batch-packed
 * @description dpdk-97ecc1c85c95c13bc66a87435758e93406c35c48-lib/librte_vhost/virtio_net.c-vhost_reserve_avail_batch_packed CVE-2020-10725
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vdesc_addrs_1789, Variable vi_1798, ExprStmt target_1, ExprStmt target_2, PostfixIncrExpr target_3, NotExpr target_4) {
	exists(IfStmt target_0 |
		target_0.getCondition().(FunctionCall).getTarget().hasName("__builtin_expect")
		and target_0.getCondition().(FunctionCall).getArgument(0).(NotExpr).getOperand().(NotExpr).getOperand().(NotExpr).getOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vdesc_addrs_1789
		and target_0.getCondition().(FunctionCall).getArgument(0).(NotExpr).getOperand().(NotExpr).getOperand().(NotExpr).getOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_1798
		and target_0.getCondition().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and target_0.getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-1"
		and target_1.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getLocation().isBefore(target_0.getCondition().(FunctionCall).getArgument(0).(NotExpr).getOperand().(NotExpr).getOperand().(NotExpr).getOperand().(ArrayExpr).getArrayBase().(VariableAccess).getLocation())
		and target_0.getCondition().(FunctionCall).getArgument(0).(NotExpr).getOperand().(NotExpr).getOperand().(NotExpr).getOperand().(ArrayExpr).getArrayBase().(VariableAccess).getLocation().isBefore(target_2.getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayBase().(VariableAccess).getLocation())
		and target_3.getOperand().(VariableAccess).getLocation().isBefore(target_0.getCondition().(FunctionCall).getArgument(0).(NotExpr).getOperand().(NotExpr).getOperand().(NotExpr).getOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getLocation())
		and target_0.getCondition().(FunctionCall).getArgument(0).(NotExpr).getOperand().(NotExpr).getOperand().(NotExpr).getOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getLocation().isBefore(target_4.getOperand().(NotExpr).getOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vdesc_addrs_1789, Variable vi_1798, ExprStmt target_1) {
		target_1.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vdesc_addrs_1789
		and target_1.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_1798
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("vhost_iova_to_vva")
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(ValueFieldAccess).getTarget().getName()="addr"
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vi_1798
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(AddressOfExpr).getOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_1798
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(4).(Literal).getValue()="3"
}

predicate func_2(Parameter vdesc_addrs_1789, Variable vi_1798, ExprStmt target_2) {
		target_2.getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vdesc_addrs_1789
		and target_2.getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_1798
}

predicate func_3(Variable vi_1798, PostfixIncrExpr target_3) {
		target_3.getOperand().(VariableAccess).getTarget()=vi_1798
}

predicate func_4(Variable vi_1798, NotExpr target_4) {
		target_4.getOperand().(NotExpr).getOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_1798
		and target_4.getOperand().(NotExpr).getOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="len"
		and target_4.getOperand().(NotExpr).getOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(ArrayExpr).getArrayOffset().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vi_1798
}

from Function func, Parameter vdesc_addrs_1789, Variable vi_1798, ExprStmt target_1, ExprStmt target_2, PostfixIncrExpr target_3, NotExpr target_4
where
not func_0(vdesc_addrs_1789, vi_1798, target_1, target_2, target_3, target_4)
and func_1(vdesc_addrs_1789, vi_1798, target_1)
and func_2(vdesc_addrs_1789, vi_1798, target_2)
and func_3(vi_1798, target_3)
and func_4(vi_1798, target_4)
and vdesc_addrs_1789.getType().hasName("uintptr_t *")
and vi_1798.getType().hasName("uint16_t")
and vdesc_addrs_1789.getParentScope+() = func
and vi_1798.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
