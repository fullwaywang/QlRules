/**
 * @name mysql-server-ef051ecaec7451b0aa2a9f4416488693bc62a680-Dbspj__execTRANSID_AI
 * @id cpp/mysql-server/ef051ecaec7451b0aa2a9f4416488693bc62a680/dbspjexectransidai
 * @description mysql-server-ef051ecaec7451b0aa2a9f4416488693bc62a680-storage/ndb/src/kernel/blocks/dbspj/DbspjMain.cpp-Dbspj__execTRANSID_AI mysql-#33157531
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vptrI_3849, Variable vtreeNodePtr_3851, FunctionCall target_0) {
	exists(PointerFieldAccess obj_0 | obj_0=target_0.getQualifier() |
		obj_0.getTarget().getName()="m_treenode_pool"
		and obj_0.getQualifier() instanceof ThisExpr
	)
	and target_0.getTarget().hasName("getPtr")
	and not target_0.getTarget().hasName("progError")
	and target_0.getArgument(0).(VariableAccess).getTarget()=vtreeNodePtr_3851
	and target_0.getArgument(1).(VariableAccess).getTarget()=vptrI_3849
}

predicate func_1(Variable vptrI_3849, Variable vtreeNodePtr_3851, ExprStmt target_9, PointerFieldAccess target_10, Function func) {
exists(IfStmt target_1 |
	exists(FunctionCall obj_0 | obj_0=target_1.getCondition() |
		exists(FunctionCall obj_1 | obj_1=obj_0.getArgument(0) |
			obj_1.getTarget().hasName("getGuardedPtr")
			and obj_1.getQualifier() instanceof ThisExpr
			and obj_1.getArgument(0).(VariableAccess).getTarget()=vtreeNodePtr_3851
			and obj_1.getArgument(1).(VariableAccess).getTarget()=vptrI_3849
		)
		and obj_0.getTarget().hasName("likely")
	)
	and exists(BlockStmt obj_2 | obj_2=target_1.getElse() |
		exists(DoStmt obj_3 | obj_3=obj_2.getStmt(0) |
			exists(BlockStmt obj_4 | obj_4=obj_3.getStmt() |
				obj_4.getStmt(3).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="theEmulatedJamIndex"
				and obj_4.getStmt(4).(ExprStmt).getExpr() instanceof Literal
				and obj_4.getStmt(5).(ExprStmt).getExpr() instanceof Literal
			)
			and obj_3.getCondition() instanceof Literal
		)
		and exists(ExprStmt obj_5 | obj_5=obj_2.getStmt(1) |
			exists(FunctionCall obj_6 | obj_6=obj_5.getExpr() |
				obj_6.getTarget().hasName("progError")
				and obj_6.getQualifier().(ThisExpr).getType() instanceof PointerType
				and obj_6.getArgument(0) instanceof Literal
				and obj_6.getArgument(1).(Literal).getValue()="2341"
				and obj_6.getArgument(2) instanceof StringLiteral
				and obj_6.getArgument(3).(StringLiteral).getValue()="getGuardedPtr(treeNodePtr, ptrI)"
			)
		)
	)
	and func.getEntryPoint().(BlockStmt).getAStmt()=target_1
	and target_1.getLocation().isBefore(target_9.getLocation())
	and target_1.getCondition().(FunctionCall).getArgument(0).(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_10.getQualifier().(ValueFieldAccess).getQualifier().(VariableAccess).getLocation())
)
}

predicate func_5(ExprStmt target_9, Function func) {
exists(EmptyStmt target_5 |
	func.getEntryPoint().(BlockStmt).getAStmt()=target_5
	and target_5.getLocation().isBefore(target_9.getLocation())
)
}

predicate func_6(Function func, ThisExpr target_6) {
	target_6.getType() instanceof PointerType
	and target_6.getEnclosingFunction() = func
}

predicate func_7(Variable vtreeNodePtr_3851, VariableAccess target_7) {
	target_7.getTarget()=vtreeNodePtr_3851
	and target_7.getParent().(FunctionCall).getParent().(ExprStmt).getExpr() instanceof FunctionCall
}

predicate func_8(Variable vptrI_3849, VariableAccess target_8) {
	target_8.getTarget()=vptrI_3849
	and target_8.getParent().(FunctionCall).getParent().(ExprStmt).getExpr() instanceof FunctionCall
}

predicate func_9(Function func, ExprStmt target_9) {
	target_9.getExpr() instanceof FunctionCall
	and target_9.getEnclosingFunction() = func
}

predicate func_10(Variable vtreeNodePtr_3851, PointerFieldAccess target_10) {
	exists(ValueFieldAccess obj_0 | obj_0=target_10.getQualifier() |
		obj_0.getTarget().getName()="p"
		and obj_0.getQualifier().(VariableAccess).getTarget()=vtreeNodePtr_3851
	)
	and target_10.getTarget().getName()="m_requestPtrI"
}

from Function func, Variable vptrI_3849, Variable vtreeNodePtr_3851, FunctionCall target_0, ThisExpr target_6, VariableAccess target_7, VariableAccess target_8, ExprStmt target_9, PointerFieldAccess target_10
where
func_0(vptrI_3849, vtreeNodePtr_3851, target_0)
and not func_1(vptrI_3849, vtreeNodePtr_3851, target_9, target_10, func)
and not func_5(target_9, func)
and func_6(func, target_6)
and func_7(vtreeNodePtr_3851, target_7)
and func_8(vptrI_3849, target_8)
and func_9(func, target_9)
and func_10(vtreeNodePtr_3851, target_10)
and vptrI_3849.getType().hasName("Uint32")
and vtreeNodePtr_3851.getType().hasName("Ptr<TreeNode>")
and vptrI_3849.(LocalVariable).getFunction() = func
and vtreeNodePtr_3851.(LocalVariable).getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
