/**
 * @name mysql-server-ef051ecaec7451b0aa2a9f4416488693bc62a680-Dbspj__createNode
 * @id cpp/mysql-server/ef051ecaec7451b0aa2a9f4416488693bc62a680/dbspjcreatenode
 * @description mysql-server-ef051ecaec7451b0aa2a9f4416488693bc62a680-storage/ndb/src/kernel/blocks/dbspj/DbspjMain.cpp-Dbspj__createNode mysql-#33157531
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func, Literal target_0) {
	exists(FunctionCall obj_0 | obj_0=target_0.getParent() |
		exists(ExprStmt obj_1 | obj_1=obj_0.getParent() |
			exists(FunctionCall obj_2 | obj_2=obj_1.getExpr() |
				obj_2.getTarget().hasName("ndbout_c")
				and obj_2.getArgument(0).(StringLiteral).getValue()="Injecting OutOfOperations error 17005 at line %d file %s"
				and obj_2.getArgument(2).(StringLiteral).getValue()="/data/project/exp/build/cloned/mysql-server/storage/ndb/src/kernel/blocks/dbspj/DbspjMain.cpp"
			)
		)
	)
	and target_0.getValue()="2413"
	and not target_0.getValue()="2486"
	and target_0.getEnclosingFunction() = func
}

predicate func_1(Parameter vrequestPtr_2402, Parameter vtreeNodePtr_2403, FunctionCall target_2, PointerFieldAccess target_3, ExprStmt target_4) {
exists(ExprStmt target_1 |
	exists(FunctionCall obj_0 | obj_0=target_1.getExpr() |
		obj_0.getTarget().hasName("insertGuardedPtr")
		and obj_0.getQualifier().(ThisExpr).getType() instanceof PointerType
		and obj_0.getArgument(0).(VariableAccess).getTarget()=vrequestPtr_2402
		and obj_0.getArgument(1).(VariableAccess).getTarget()=vtreeNodePtr_2403
	)
	and exists(BlockStmt obj_1 | obj_1=target_1.getParent() |
		exists(IfStmt obj_2 | obj_2=obj_1.getParent() |
			obj_2.getThen().(BlockStmt).getStmt(6)=target_1
			and obj_2.getCondition()=target_2
		)
	)
	and target_3.getQualifier().(ValueFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_1.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
	and target_4.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(ReferenceFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_1.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation())
)
}

predicate func_2(Parameter vrequestPtr_2402, Parameter vtreeNodePtr_2403, FunctionCall target_2) {
	exists(PointerFieldAccess obj_0 | obj_0=target_2.getQualifier() |
		obj_0.getTarget().getName()="m_treenode_pool"
		and obj_0.getQualifier().(ThisExpr).getType() instanceof PointerType
	)
	and exists(PointerFieldAccess obj_1 | obj_1=target_2.getArgument(0) |
		exists(ValueFieldAccess obj_2 | obj_2=obj_1.getQualifier() |
			obj_2.getTarget().getName()="p"
			and obj_2.getQualifier().(VariableAccess).getTarget()=vrequestPtr_2402
		)
		and obj_1.getTarget().getName()="m_arena"
	)
	and target_2.getTarget().hasName("seize")
	and target_2.getArgument(1).(VariableAccess).getTarget()=vtreeNodePtr_2403
}

predicate func_3(Parameter vrequestPtr_2402, PointerFieldAccess target_3) {
	exists(ValueFieldAccess obj_0 | obj_0=target_3.getQualifier() |
		obj_0.getTarget().getName()="p"
		and obj_0.getQualifier().(VariableAccess).getTarget()=vrequestPtr_2402
	)
	and target_3.getTarget().getName()="m_nodes"
}

predicate func_4(Parameter vtreeNodePtr_2403, ExprStmt target_4) {
	exists(AssignExpr obj_0 | obj_0=target_4.getExpr() |
		exists(PointerFieldAccess obj_1 | obj_1=obj_0.getLValue() |
			exists(ReferenceFieldAccess obj_2 | obj_2=obj_1.getQualifier() |
				obj_2.getTarget().getName()="p"
				and obj_2.getQualifier().(VariableAccess).getTarget()=vtreeNodePtr_2403
			)
			and obj_1.getTarget().getName()="m_node_no"
		)
		and exists(ReferenceFieldAccess obj_3 | obj_3=obj_0.getRValue() |
			obj_3.getTarget().getName()="m_cnt"
			and obj_3.getQualifier().(VariableAccess).getTarget().getType().hasName("Build_context &")
		)
	)
}

from Function func, Parameter vrequestPtr_2402, Parameter vtreeNodePtr_2403, Literal target_0, FunctionCall target_2, PointerFieldAccess target_3, ExprStmt target_4
where
func_0(func, target_0)
and not func_1(vrequestPtr_2402, vtreeNodePtr_2403, target_2, target_3, target_4)
and func_2(vrequestPtr_2402, vtreeNodePtr_2403, target_2)
and func_3(vrequestPtr_2402, target_3)
and func_4(vtreeNodePtr_2403, target_4)
and vrequestPtr_2402.getType().hasName("Ptr<Request>")
and vtreeNodePtr_2403.getType().hasName("Ptr<TreeNode> &")
and vrequestPtr_2402.getFunction() = func
and vtreeNodePtr_2403.getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
