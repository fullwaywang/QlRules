/**
 * @name mysql-server-ef051ecaec7451b0aa2a9f4416488693bc62a680-Dbspj__execSCAN_HBREP
 * @id cpp/mysql-server/ef051ecaec7451b0aa2a9f4416488693bc62a680/dbspjexecscanhbrep
 * @description mysql-server-ef051ecaec7451b0aa2a9f4416488693bc62a680-storage/ndb/src/kernel/blocks/dbspj/DbspjMain.cpp-Dbspj__execSCAN_HBREP mysql-#33157531
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vsenderData_3651, Variable vscanFragHandlePtr_3654, FunctionCall target_0) {
	exists(PointerFieldAccess obj_0 | obj_0=target_0.getQualifier() |
		obj_0.getTarget().getName()="m_scanfraghandle_pool"
		and obj_0.getQualifier() instanceof ThisExpr
	)
	and target_0.getTarget().hasName("getPtr")
	and not target_0.getTarget().hasName("progError")
	and target_0.getArgument(0).(VariableAccess).getTarget()=vscanFragHandlePtr_3654
	and target_0.getArgument(1).(VariableAccess).getTarget()=vsenderData_3651
}

predicate func_1(Variable vsenderData_3651, Variable vscanFragHandlePtr_3654, ExprStmt target_10, PointerFieldAccess target_11, Function func) {
exists(IfStmt target_1 |
	exists(FunctionCall obj_0 | obj_0=target_1.getCondition() |
		exists(FunctionCall obj_1 | obj_1=obj_0.getArgument(0) |
			obj_1.getTarget().hasName("getGuardedPtr")
			and obj_1.getQualifier() instanceof ThisExpr
			and obj_1.getArgument(0).(VariableAccess).getTarget()=vscanFragHandlePtr_3654
			and obj_1.getArgument(1).(VariableAccess).getTarget()=vsenderData_3651
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
				and obj_6.getArgument(3).(StringLiteral).getValue()="getGuardedPtr(scanFragHandlePtr, senderData)"
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

predicate func_7(Function func, ThisExpr target_7) {
	target_7.getType() instanceof PointerType
	and target_7.getEnclosingFunction() = func
}

predicate func_8(Variable vscanFragHandlePtr_3654, VariableAccess target_8) {
	target_8.getTarget()=vscanFragHandlePtr_3654
	and target_8.getParent().(FunctionCall).getParent().(ExprStmt).getExpr() instanceof FunctionCall
}

predicate func_9(Variable vsenderData_3651, VariableAccess target_9) {
	target_9.getTarget()=vsenderData_3651
	and target_9.getParent().(FunctionCall).getParent().(ExprStmt).getExpr() instanceof FunctionCall
}

predicate func_10(Function func, ExprStmt target_10) {
	target_10.getExpr() instanceof FunctionCall
	and target_10.getEnclosingFunction() = func
}

predicate func_11(Variable vscanFragHandlePtr_3654, PointerFieldAccess target_11) {
	exists(ValueFieldAccess obj_0 | obj_0=target_11.getQualifier() |
		obj_0.getTarget().getName()="p"
		and obj_0.getQualifier().(VariableAccess).getTarget()=vscanFragHandlePtr_3654
	)
	and target_11.getTarget().getName()="m_treeNodePtrI"
}

from Function func, Variable vsenderData_3651, Variable vscanFragHandlePtr_3654, FunctionCall target_0, ThisExpr target_7, VariableAccess target_8, VariableAccess target_9, ExprStmt target_10, PointerFieldAccess target_11
where
func_0(vsenderData_3651, vscanFragHandlePtr_3654, target_0)
and not func_1(vsenderData_3651, vscanFragHandlePtr_3654, target_10, target_11, func)
and not func_6(target_10, func)
and func_7(func, target_7)
and func_8(vscanFragHandlePtr_3654, target_8)
and func_9(vsenderData_3651, target_9)
and func_10(func, target_10)
and func_11(vscanFragHandlePtr_3654, target_11)
and vsenderData_3651.getType().hasName("Uint32")
and vscanFragHandlePtr_3654.getType().hasName("Ptr<ScanFragHandle>")
and vsenderData_3651.(LocalVariable).getFunction() = func
and vscanFragHandlePtr_3654.(LocalVariable).getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
