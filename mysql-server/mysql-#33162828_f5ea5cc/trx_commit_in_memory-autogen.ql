/**
 * @name mysql-server-f5ea5cc09ac64cdfe17d6c51fa07648f33d79842-trx_commit_in_memory
 * @id cpp/mysql-server/f5ea5cc09ac64cdfe17d6c51fa07648f33d79842/trxcommitinmemory
 * @description mysql-server-f5ea5cc09ac64cdfe17d6c51fa07648f33d79842-storage/innobase/trx/trx0trx.cc-trx_commit_in_memory mysql-#33162828
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vrseg_1976, Parameter vtrx_1906, IfStmt target_0) {
	exists(EqualityOperation obj_0 | obj_0=target_0.getCondition() |
		exists(ValueFieldAccess obj_1 | obj_1=obj_0.getLeftOperand() |
			exists(ValueFieldAccess obj_2 | obj_2=obj_1.getQualifier() |
				exists(PointerFieldAccess obj_3 | obj_3=obj_2.getQualifier() |
					obj_3.getTarget().getName()="rsegs"
					and obj_3.getQualifier().(VariableAccess).getTarget()=vtrx_1906
				)
				and obj_2.getTarget().getName()="m_redo"
			)
			and obj_1.getTarget().getName()="rseg"
		)
		and obj_0.getRightOperand().(Literal).getValue()="0"
	)
	and exists(BlockStmt obj_4 | obj_4=target_0.getThen() |
		exists(ExprStmt obj_5 | obj_5=obj_4.getStmt(2) |
			exists(FunctionCall obj_6 | obj_6=obj_5.getExpr() |
				exists(PointerFieldAccess obj_7 | obj_7=obj_6.getQualifier() |
					obj_7.getTarget().getName()="trx_ref_count"
					and obj_7.getQualifier().(VariableAccess).getTarget()=vrseg_1976
				)
				and obj_6.getTarget().hasName("operator--")
				and obj_6.getArgument(0).(Literal).getValue()="0"
			)
		)
	)
	and target_0.getFollowingStmt() instanceof DeclStmt
}

predicate func_1(Parameter vtrx_1906, EqualityOperation target_2, ValueFieldAccess target_3, ExprStmt target_4) {
exists(ExprStmt target_1 |
	exists(AssignExpr obj_0 | obj_0=target_1.getExpr() |
		exists(ValueFieldAccess obj_1 | obj_1=obj_0.getLValue() |
			exists(ValueFieldAccess obj_2 | obj_2=obj_1.getQualifier() |
				exists(PointerFieldAccess obj_3 | obj_3=obj_2.getQualifier() |
					obj_3.getTarget().getName()="rsegs"
					and obj_3.getQualifier().(VariableAccess).getTarget()=vtrx_1906
				)
				and obj_2.getTarget().getName()="m_redo"
			)
			and obj_1.getTarget().getName()="rseg"
		)
		and obj_0.getRValue().(Literal).getValue()="0"
	)
	and exists(BlockStmt obj_4 | obj_4=target_1.getParent() |
		exists(IfStmt obj_5 | obj_5=obj_4.getParent() |
			obj_5.getThen().(BlockStmt).getStmt(3)=target_1
			and obj_5.getCondition()=target_2
		)
	)
	and target_3.getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_1.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
	and target_1.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_4.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
)
}

predicate func_2(Parameter vtrx_1906, EqualityOperation target_2) {
	exists(ValueFieldAccess obj_0 | obj_0=target_2.getLeftOperand() |
		exists(ValueFieldAccess obj_1 | obj_1=obj_0.getQualifier() |
			exists(PointerFieldAccess obj_2 | obj_2=obj_1.getQualifier() |
				obj_2.getTarget().getName()="rsegs"
				and obj_2.getQualifier().(VariableAccess).getTarget()=vtrx_1906
			)
			and obj_1.getTarget().getName()="m_redo"
		)
		and obj_0.getTarget().getName()="rseg"
	)
	and target_2.getRightOperand().(Literal).getValue()="0"
}

predicate func_3(Parameter vtrx_1906, ValueFieldAccess target_3) {
	exists(ValueFieldAccess obj_0 | obj_0=target_3.getQualifier() |
		exists(PointerFieldAccess obj_1 | obj_1=obj_0.getQualifier() |
			obj_1.getTarget().getName()="rsegs"
			and obj_1.getQualifier().(VariableAccess).getTarget()=vtrx_1906
		)
		and obj_0.getTarget().getName()="m_redo"
	)
	and target_3.getTarget().getName()="rseg"
}

predicate func_4(Parameter vtrx_1906, ExprStmt target_4) {
	exists(FunctionCall obj_0 | obj_0=target_4.getExpr() |
		obj_0.getTarget().hasName("set_persist_gtid")
		and obj_0.getQualifier().(VariableAccess).getTarget().getType().hasName("Clone_persist_gtid &")
		and obj_0.getArgument(0).(VariableAccess).getTarget()=vtrx_1906
		and obj_0.getArgument(1).(Literal).getValue()="0"
	)
}

from Function func, Variable vrseg_1976, Parameter vtrx_1906, IfStmt target_0, EqualityOperation target_2, ValueFieldAccess target_3, ExprStmt target_4
where
func_0(vrseg_1976, vtrx_1906, target_0)
and not func_1(vtrx_1906, target_2, target_3, target_4)
and func_2(vtrx_1906, target_2)
and func_3(vtrx_1906, target_3)
and func_4(vtrx_1906, target_4)
and vrseg_1976.getType().hasName("trx_rseg_t *")
and vtrx_1906.getType().hasName("trx_t *")
and vrseg_1976.(LocalVariable).getFunction() = func
and vtrx_1906.getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
