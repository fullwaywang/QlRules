/**
 * @name mysql-server-ef051ecaec7451b0aa2a9f4416488693bc62a680-Dbspj__cleanup
 * @id cpp/mysql-server/ef051ecaec7451b0aa2a9f4416488693bc62a680/dbspjcleanup
 * @description mysql-server-ef051ecaec7451b0aa2a9f4416488693bc62a680-storage/ndb/src/kernel/blocks/dbspj/DbspjMain.cpp-Dbspj__cleanup mysql-#33157531
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vnodePtr_3401, ExprStmt target_1, ExprStmt target_2) {
exists(ExprStmt target_0 |
	exists(FunctionCall obj_0 | obj_0=target_0.getExpr() |
		obj_0.getTarget().hasName("removeGuardedPtr")
		and obj_0.getQualifier().(ThisExpr).getType() instanceof PointerType
		and obj_0.getArgument(0).(VariableAccess).getTarget()=vnodePtr_3401
	)
	and target_0.getLocation().isBefore(target_1.getLocation())
	and target_2.getExpr().(ExprCall).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
)
}

predicate func_1(Variable vnodePtr_3401, ExprStmt target_1) {
	exists(FunctionCall obj_0 | obj_0=target_1.getExpr() |
		exists(PointerFieldAccess obj_1 | obj_1=obj_0.getQualifier() |
			obj_1.getTarget().getName()="m_treenode_pool"
			and obj_1.getQualifier().(ThisExpr).getType() instanceof PointerType
		)
		and obj_0.getTarget().hasName("release")
		and obj_0.getArgument(0).(VariableAccess).getTarget()=vnodePtr_3401
	)
}

predicate func_2(Variable vnodePtr_3401, ExprStmt target_2) {
	exists(ExprCall obj_0 | obj_0=target_2.getExpr() |
		exists(PointerFieldAccess obj_1 | obj_1=obj_0.getQualifier() |
			exists(PointerFieldAccess obj_2 | obj_2=obj_1.getQualifier() |
				exists(ValueFieldAccess obj_3 | obj_3=obj_2.getQualifier() |
					obj_3.getTarget().getName()="p"
					and obj_3.getQualifier().(VariableAccess).getTarget()=vnodePtr_3401
				)
				and obj_2.getTarget().getName()="m_info"
			)
			and obj_1.getTarget().getName()="m_cleanup"
		)
		and obj_0.getExpr().(ThisExpr).getType() instanceof PointerType
		and obj_0.getArgument(0).(VariableAccess).getTarget().getType().hasName("Ptr<Request>")
		and obj_0.getArgument(1).(VariableAccess).getTarget()=vnodePtr_3401
	)
}

from Function func, Variable vnodePtr_3401, ExprStmt target_1, ExprStmt target_2
where
not func_0(vnodePtr_3401, target_1, target_2)
and func_1(vnodePtr_3401, target_1)
and func_2(vnodePtr_3401, target_2)
and vnodePtr_3401.getType().hasName("Ptr<TreeNode>")
and vnodePtr_3401.(LocalVariable).getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
