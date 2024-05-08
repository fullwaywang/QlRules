/**
 * @name mysql-server-f5ea5cc09ac64cdfe17d6c51fa07648f33d79842-trx_undo_insert_cleanup
 * @id cpp/mysql-server/f5ea5cc09ac64cdfe17d6c51fa07648f33d79842/trxundoinsertcleanup
 * @description mysql-server-f5ea5cc09ac64cdfe17d6c51fa07648f33d79842-storage/innobase/trx/trx0undo.cc-trx_undo_insert_cleanup mysql-#33162828
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(EqualityOperation target_1, Function func) {
exists(EmptyStmt target_0 |
	exists(BlockStmt obj_0 | obj_0=target_0.getParent() |
		exists(IfStmt obj_1 | obj_1=obj_0.getParent() |
			obj_1.getElse().(BlockStmt).getStmt(2)=target_0
			and obj_1.getCondition()=target_1
		)
	)
	and target_0.getEnclosingFunction() = func
)
}

predicate func_1(Function func, EqualityOperation target_1) {
	exists(PointerFieldAccess obj_0 | obj_0=target_1.getLeftOperand() |
		obj_0.getTarget().getName()="state"
		and obj_0.getQualifier().(VariableAccess).getTarget().getType().hasName("trx_undo_t *")
	)
	and target_1.getRightOperand().(Literal).getValue()="2"
	and target_1.getEnclosingFunction() = func
}

from Function func, EqualityOperation target_1
where
not func_0(target_1, func)
and func_1(func, target_1)
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
