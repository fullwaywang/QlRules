/**
 * @name mysql-server-70cf38f9528fc577905053dbe95782463baff9c7-Gtid_state__get_automatic_gno_
 * @id cpp/mysql-server/70cf38f9528fc577905053dbe95782463baff9c7/gtidstategetautomaticgno
 * @description mysql-server-70cf38f9528fc577905053dbe95782463baff9c7-sql/rpl_slave.cc-Gtid_state__get_automatic_gno_ mysql-#32103192
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vMAX_GNO, VariableAccess target_0) {
	target_0.getTarget()=vMAX_GNO
}

predicate func_1(Variable viv_473, ExprStmt target_5) {
exists(RelationalOperation target_1 |
	exists(PointerFieldAccess obj_0 | obj_0=target_1.getGreaterOperand() |
		obj_0.getTarget().getName()="end"
		and obj_0.getQualifier().(VariableAccess).getTarget()=viv_473
	)
	and  (target_1 instanceof GTExpr or target_1 instanceof LTExpr)
	and target_1.getLesserOperand() instanceof ValueFieldAccess
	and target_1.getParent().(IfStmt).getThen()=target_5
)
}

/*predicate func_2(Variable vnext_candidate_469, ValueFieldAccess target_2) {
	target_2.getTarget().getName()="gno"
	and target_2.getQualifier().(VariableAccess).getTarget()=vnext_candidate_469
}

*/
predicate func_3(Variable vnext_candidate_469, Variable viv_473, ExprStmt target_5, PointerFieldAccess target_3) {
	exists(LEExpr obj_0 | obj_0=target_3.getParent() |
		exists(ValueFieldAccess obj_1 | obj_1=obj_0.getLesserOperand() |
			obj_1.getTarget().getName()="gno"
			and obj_1.getQualifier().(VariableAccess).getTarget()=vnext_candidate_469
		)
		and obj_0.getParent().(IfStmt).getThen()=target_5
	)
	and target_3.getTarget().getName()="end"
	and target_3.getQualifier().(VariableAccess).getTarget()=viv_473
}

predicate func_4(Variable viv_473, ExprStmt target_5, RelationalOperation target_4) {
	exists(PointerFieldAccess obj_0 | obj_0=target_4.getGreaterOperand() |
		obj_0.getTarget().getName()="end"
		and obj_0.getQualifier().(VariableAccess).getTarget()=viv_473
	)
	and  (target_4 instanceof GEExpr or target_4 instanceof LEExpr)
	and target_4.getLesserOperand() instanceof ValueFieldAccess
	and target_4.getParent().(IfStmt).getThen()=target_5
}

predicate func_5(Variable vnext_candidate_469, Variable viv_473, ExprStmt target_5) {
	exists(AssignExpr obj_0 | obj_0=target_5.getExpr() |
		exists(ValueFieldAccess obj_1 | obj_1=obj_0.getLValue() |
			obj_1.getTarget().getName()="gno"
			and obj_1.getQualifier().(VariableAccess).getTarget()=vnext_candidate_469
		)
		and exists(PointerFieldAccess obj_2 | obj_2=obj_0.getRValue() |
			obj_2.getTarget().getName()="end"
			and obj_2.getQualifier().(VariableAccess).getTarget()=viv_473
		)
	)
}

from Function func, Variable vnext_candidate_469, Variable viv_473, Variable vMAX_GNO, VariableAccess target_0, PointerFieldAccess target_3, RelationalOperation target_4, ExprStmt target_5
where
func_0(vMAX_GNO, target_0)
and not func_1(viv_473, target_5)
and func_3(vnext_candidate_469, viv_473, target_5, target_3)
and func_4(viv_473, target_5, target_4)
and func_5(vnext_candidate_469, viv_473, target_5)
and vnext_candidate_469.getType().hasName("Gtid")
and viv_473.getType().hasName("const Interval *")
and vMAX_GNO.getType().hasName("rpl_gno")
and vnext_candidate_469.(LocalVariable).getFunction() = func
and viv_473.(LocalVariable).getFunction() = func
and not vMAX_GNO.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
