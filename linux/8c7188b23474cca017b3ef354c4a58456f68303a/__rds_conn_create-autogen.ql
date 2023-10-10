/**
 * @name linux-8c7188b23474cca017b3ef354c4a58456f68303a-__rds_conn_create
 * @id cpp/linux/8c7188b23474cca017b3ef354c4a58456f68303a/--rds-conn-create
 * @description linux-8c7188b23474cca017b3ef354c4a58456f68303a-__rds_conn_create CVE-2015-6937
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vrds_conn_slab, Variable vconn_126) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(FunctionCall).getTarget().hasName("kmem_cache_free")
		and target_0.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vrds_conn_slab
		and target_0.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vconn_126
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition() instanceof EqualityOperation)
}

predicate func_1(Parameter vtrans_123, Variable vconn_126, Function func) {
	exists(IfStmt target_1 |
		target_1.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vtrans_123
		and target_1.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_1.getThen().(BlockStmt).getStmt(0) instanceof ExprStmt
		and target_1.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vconn_126
		and target_1.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("ERR_PTR")
		and target_1.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(UnaryMinusExpr).getOperand().(Literal).getValue()="19"
		and target_1.getThen().(BlockStmt).getStmt(2).(GotoStmt).toString() = "goto ..."
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_1)
}

from Function func, Variable vrds_conn_slab, Parameter vtrans_123, Variable vconn_126
where
func_0(vrds_conn_slab, vconn_126)
and func_1(vtrans_123, vconn_126, func)
and vrds_conn_slab.getType().hasName("kmem_cache *")
and vtrans_123.getType().hasName("rds_transport *")
and vconn_126.getType().hasName("rds_connection *")
and not vrds_conn_slab.getParentScope+() = func
and vtrans_123.getParentScope+() = func
and vconn_126.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
