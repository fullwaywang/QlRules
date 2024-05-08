/**
 * @name mysql-server-b37ddc746c429df960464f16dd6d85999530b1ab-recv_scan_log_recs
 * @id cpp/mysql-server/b37ddc746c429df960464f16dd6d85999530b1ab/recvscanlogrecs
 * @description mysql-server-b37ddc746c429df960464f16dd6d85999530b1ab-storage/innobase/log/log0recv.cc-recv_scan_log_recs mysql-#33945602
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(RelationalOperation target_1, Function func) {
exists(DoStmt target_0 |
	exists(BlockStmt obj_0 | obj_0=target_0.getParent() |
		exists(IfStmt obj_1 | obj_1=obj_0.getParent() |
			obj_1.getThen().(BlockStmt).getStmt(1)=target_0
			and obj_1.getCondition()=target_1
		)
	)
	and target_0.getCondition().(Literal).getValue()="0"
	and target_0.getEnclosingFunction() = func
)
}

predicate func_1(Function func, RelationalOperation target_1) {
	exists(PointerFieldAccess obj_0 | obj_0=target_1.getLesserOperand() |
		obj_0.getTarget().getName()="scanned_lsn"
		and obj_0.getQualifier().(VariableAccess).getTarget().getType().hasName("recv_sys_t *")
	)
	and  (target_1 instanceof GTExpr or target_1 instanceof LTExpr)
	and target_1.getGreaterOperand().(VariableAccess).getTarget().getType().hasName("lsn_t")
	and target_1.getEnclosingFunction() = func
}

from Function func, RelationalOperation target_1
where
not func_0(target_1, func)
and func_1(func, target_1)
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
