/**
 * @name mysql-server-ef051ecaec7451b0aa2a9f4416488693bc62a680-Dbspj__execLQHKEYCONF
 * @id cpp/mysql-server/ef051ecaec7451b0aa2a9f4416488693bc62a680/dbspjexeclqhkeyconf
 * @description mysql-server-ef051ecaec7451b0aa2a9f4416488693bc62a680-storage/ndb/src/kernel/blocks/dbspj/DbspjMain.cpp-Dbspj__execLQHKEYCONF mysql-#33157531
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vconf_3594, Variable vtreeNodePtr_3595, FunctionCall target_0) {
	exists(PointerFieldAccess obj_0 | obj_0=target_0.getQualifier() |
		obj_0.getTarget().getName()="m_treenode_pool"
		and obj_0.getQualifier() instanceof ThisExpr
	)
	and exists(PointerFieldAccess obj_1 | obj_1=target_0.getArgument(1) |
		obj_1.getTarget().getName()="opPtr"
		and obj_1.getQualifier().(VariableAccess).getTarget()=vconf_3594
	)
	and target_0.getTarget().hasName("getPtr")
	and not target_0.getTarget().hasName("progError")
	and target_0.getArgument(0).(VariableAccess).getTarget()=vtreeNodePtr_3595
}

predicate func_1(Variable vconf_3594, Variable vtreeNodePtr_3595, ExprStmt target_10, PointerFieldAccess target_11, Function func) {
exists(IfStmt target_1 |
	exists(FunctionCall obj_0 | obj_0=target_1.getCondition() |
		exists(FunctionCall obj_1 | obj_1=obj_0.getArgument(0) |
			exists(PointerFieldAccess obj_2 | obj_2=obj_1.getArgument(1) |
				obj_2.getTarget().getName()="opPtr"
				and obj_2.getQualifier().(VariableAccess).getTarget()=vconf_3594
			)
			and obj_1.getTarget().hasName("getGuardedPtr")
			and obj_1.getQualifier() instanceof ThisExpr
			and obj_1.getArgument(0).(VariableAccess).getTarget()=vtreeNodePtr_3595
		)
		and obj_0.getTarget().hasName("likely")
	)
	and exists(BlockStmt obj_3 | obj_3=target_1.getElse() |
		exists(DoStmt obj_4 | obj_4=obj_3.getStmt(0) |
			exists(BlockStmt obj_5 | obj_5=obj_4.getStmt() |
				obj_5.getStmt(3).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="theEmulatedJamIndex"
				and obj_5.getStmt(4).(ExprStmt).getExpr() instanceof Literal
				and obj_5.getStmt(5).(ExprStmt).getExpr() instanceof Literal
			)
			and obj_4.getCondition() instanceof Literal
		)
		and exists(ExprStmt obj_6 | obj_6=obj_3.getStmt(1) |
			exists(FunctionCall obj_7 | obj_7=obj_6.getExpr() |
				obj_7.getTarget().hasName("progError")
				and obj_7.getQualifier().(ThisExpr).getType() instanceof PointerType
				and obj_7.getArgument(0) instanceof Literal
				and obj_7.getArgument(1).(Literal).getValue()="2341"
				and obj_7.getArgument(2) instanceof StringLiteral
				and obj_7.getArgument(3).(StringLiteral).getValue()="getGuardedPtr(treeNodePtr, conf->opPtr)"
			)
		)
	)
	and func.getEntryPoint().(BlockStmt).getAStmt()=target_1
	and target_1.getLocation().isBefore(target_10.getLocation())
	and target_1.getCondition().(FunctionCall).getArgument(0).(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_11.getQualifier().(ValueFieldAccess).getQualifier().(VariableAccess).getLocation())
)
}

predicate func_6(ExprStmt target_10, Function func) {
exists(EmptyStmt target_6 |
	func.getEntryPoint().(BlockStmt).getAStmt()=target_6
	and target_6.getLocation().isBefore(target_10.getLocation())
)
}

predicate func_7(Variable vconf_3594, PointerFieldAccess target_7) {
	target_7.getTarget().getName()="opPtr"
	and target_7.getQualifier().(VariableAccess).getTarget()=vconf_3594
	and target_7.getParent().(FunctionCall).getParent().(ExprStmt).getExpr() instanceof FunctionCall
}

predicate func_8(Function func, ThisExpr target_8) {
	target_8.getType() instanceof PointerType
	and target_8.getEnclosingFunction() = func
}

predicate func_9(Variable vtreeNodePtr_3595, VariableAccess target_9) {
	target_9.getTarget()=vtreeNodePtr_3595
	and target_9.getParent().(FunctionCall).getParent().(ExprStmt).getExpr() instanceof FunctionCall
}

predicate func_10(Function func, ExprStmt target_10) {
	target_10.getExpr() instanceof FunctionCall
	and target_10.getEnclosingFunction() = func
}

predicate func_11(Variable vtreeNodePtr_3595, PointerFieldAccess target_11) {
	exists(ValueFieldAccess obj_0 | obj_0=target_11.getQualifier() |
		obj_0.getTarget().getName()="p"
		and obj_0.getQualifier().(VariableAccess).getTarget()=vtreeNodePtr_3595
	)
	and target_11.getTarget().getName()="m_requestPtrI"
}

from Function func, Variable vconf_3594, Variable vtreeNodePtr_3595, FunctionCall target_0, PointerFieldAccess target_7, ThisExpr target_8, VariableAccess target_9, ExprStmt target_10, PointerFieldAccess target_11
where
func_0(vconf_3594, vtreeNodePtr_3595, target_0)
and not func_1(vconf_3594, vtreeNodePtr_3595, target_10, target_11, func)
and not func_6(target_10, func)
and func_7(vconf_3594, target_7)
and func_8(func, target_8)
and func_9(vtreeNodePtr_3595, target_9)
and func_10(func, target_10)
and func_11(vtreeNodePtr_3595, target_11)
and vconf_3594.getType().hasName("const LqhKeyConf *")
and vtreeNodePtr_3595.getType().hasName("Ptr<TreeNode>")
and vconf_3594.(LocalVariable).getFunction() = func
and vtreeNodePtr_3595.(LocalVariable).getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
