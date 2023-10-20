/**
 * @name dpdk-3ae4beb079ce242240c34376a066bbccd0c0b23e-vhost_user_set_log_base
 * @id cpp/dpdk/3ae4beb079ce242240c34376a066bbccd0c0b23e/vhost-user-set-log-base
 * @description dpdk-3ae4beb079ce242240c34376a066bbccd0c0b23e-lib/librte_vhost/vhost_user.c-vhost_user_set_log_base CVE-2020-10722
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func, StringLiteral target_0) {
		target_0.getValue()="VHOST_CONFIG: log offset %#lx exceeds log size %#lx\n"
		and not target_0.getValue()="VHOST_CONFIG: log offset %#lx and log size %#lx overflow\n"
		and target_0.getEnclosingFunction() = func
}

predicate func_1(Variable vsize_2050, Variable voff_2050, BlockStmt target_5, ExprStmt target_6, ExprStmt target_7, ExprStmt target_8) {
	exists(RelationalOperation target_1 |
		 (target_1 instanceof GEExpr or target_1 instanceof LEExpr)
		and target_1.getGreaterOperand().(VariableAccess).getTarget()=voff_2050
		and target_1.getLesserOperand().(UnaryMinusExpr).getOperand().(VariableAccess).getTarget()=vsize_2050
		and target_1.getParent().(IfStmt).getThen()=target_5
		and target_6.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_1.getLesserOperand().(UnaryMinusExpr).getOperand().(VariableAccess).getLocation())
		and target_1.getLesserOperand().(UnaryMinusExpr).getOperand().(VariableAccess).getLocation().isBefore(target_7.getExpr().(FunctionCall).getArgument(4).(VariableAccess).getLocation())
		and target_8.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_1.getGreaterOperand().(VariableAccess).getLocation()))
}

/*predicate func_2(Variable vsize_2050, Variable voff_2050, BlockStmt target_5, VariableAccess target_2) {
		target_2.getTarget()=voff_2050
		and target_2.getParent().(GTExpr).getLesserOperand().(VariableAccess).getTarget()=vsize_2050
		and target_2.getParent().(GTExpr).getParent().(IfStmt).getThen()=target_5
}

*/
/*predicate func_3(Variable vsize_2050, Variable voff_2050, BlockStmt target_5, VariableAccess target_3) {
		target_3.getTarget()=vsize_2050
		and target_3.getParent().(GTExpr).getGreaterOperand().(VariableAccess).getTarget()=voff_2050
		and target_3.getParent().(GTExpr).getParent().(IfStmt).getThen()=target_5
}

*/
predicate func_4(Variable vsize_2050, Variable voff_2050, BlockStmt target_5, RelationalOperation target_4) {
		 (target_4 instanceof GTExpr or target_4 instanceof LTExpr)
		and target_4.getGreaterOperand().(VariableAccess).getTarget()=voff_2050
		and target_4.getLesserOperand().(VariableAccess).getTarget()=vsize_2050
		and target_4.getParent().(IfStmt).getThen()=target_5
}

predicate func_5(Variable vsize_2050, Variable voff_2050, BlockStmt target_5) {
		target_5.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("rte_log")
		and target_5.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(Literal).getValue()="4"
		and target_5.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2) instanceof StringLiteral
		and target_5.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=voff_2050
		and target_5.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vsize_2050
}

predicate func_6(Variable vsize_2050, ExprStmt target_6) {
		target_6.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vsize_2050
		and target_6.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getTarget().getName()="mmap_size"
		and target_6.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="log"
		and target_6.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="payload"
}

predicate func_7(Variable vsize_2050, Variable voff_2050, ExprStmt target_7) {
		target_7.getExpr().(FunctionCall).getTarget().hasName("rte_log")
		and target_7.getExpr().(FunctionCall).getArgument(0).(Literal).getValue()="4"
		and target_7.getExpr().(FunctionCall).getArgument(2) instanceof StringLiteral
		and target_7.getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=voff_2050
		and target_7.getExpr().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vsize_2050
}

predicate func_8(Variable voff_2050, ExprStmt target_8) {
		target_8.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=voff_2050
		and target_8.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getTarget().getName()="mmap_offset"
		and target_8.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="log"
		and target_8.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="payload"
}

from Function func, Variable vsize_2050, Variable voff_2050, StringLiteral target_0, RelationalOperation target_4, BlockStmt target_5, ExprStmt target_6, ExprStmt target_7, ExprStmt target_8
where
func_0(func, target_0)
and not func_1(vsize_2050, voff_2050, target_5, target_6, target_7, target_8)
and func_4(vsize_2050, voff_2050, target_5, target_4)
and func_5(vsize_2050, voff_2050, target_5)
and func_6(vsize_2050, target_6)
and func_7(vsize_2050, voff_2050, target_7)
and func_8(voff_2050, target_8)
and vsize_2050.getType().hasName("uint64_t")
and voff_2050.getType().hasName("uint64_t")
and vsize_2050.getParentScope+() = func
and voff_2050.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
