/**
 * @name mysql-server-ef051ecaec7451b0aa2a9f4416488693bc62a680-Dbspj__execCONTINUEB
 * @id cpp/mysql-server/ef051ecaec7451b0aa2a9f4416488693bc62a680/dbspjexeccontinueb
 * @description mysql-server-ef051ecaec7451b0aa2a9f4416488693bc62a680-storage/ndb/src/kernel/blocks/dbspj/DbspjMain.cpp-Dbspj__execCONTINUEB mysql-#33157531
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vtreeNodePtr_773, FunctionCall target_0) {
	exists(PointerFieldAccess obj_0 | obj_0=target_0.getQualifier() |
		obj_0.getTarget().getName()="m_treenode_pool"
		and obj_0.getQualifier() instanceof ThisExpr
	)
	and target_0.getTarget().hasName("getPtr")
	and not target_0.getTarget().hasName("progError")
	and target_0.getArgument(0).(VariableAccess).getTarget()=vtreeNodePtr_773
	and target_0.getArgument(1) instanceof ArrayExpr
}

predicate func_1(Variable vtreeNodePtr_773, ExprStmt target_11, PointerFieldAccess target_12) {
exists(IfStmt target_1 |
	exists(FunctionCall obj_0 | obj_0=target_1.getCondition() |
		exists(FunctionCall obj_1 | obj_1=obj_0.getArgument(0) |
			obj_1.getTarget().hasName("getGuardedPtr")
			and obj_1.getQualifier() instanceof ThisExpr
			and obj_1.getArgument(0).(VariableAccess).getTarget()=vtreeNodePtr_773
			and obj_1.getArgument(1) instanceof ArrayExpr
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
				and obj_6.getArgument(3).(StringLiteral).getValue()="getGuardedPtr(treeNodePtr, signal->theData[1])"
			)
		)
	)
	and target_1.getLocation().isBefore(target_11.getLocation())
	and target_1.getCondition().(FunctionCall).getArgument(0).(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_12.getQualifier().(ValueFieldAccess).getQualifier().(VariableAccess).getLocation())
)
}

/*predicate func_2(Function func) {
exists(AssignExpr target_2 |
	exists(ArrayExpr obj_0 | obj_0=target_2.getLValue() |
		exists(PointerFieldAccess obj_1 | obj_1=obj_0.getArrayBase() |
			obj_1.getTarget().getName()="theEmulatedJam"
			and obj_1.getQualifier().(VariableAccess).getType().hasName("EmulatedJamBuffer *")
		)
		and obj_0.getArrayOffset().(PostfixIncrExpr).getOperand().(VariableAccess).getType().hasName("Uint32")
	)
	and exists(ConstructorCall obj_2 | obj_2=target_2.getRValue() |
		obj_2.getArgument(0) instanceof Literal
		and obj_2.getArgument(1) instanceof Literal
	)
	and target_2.getEnclosingFunction() = func
)
}

*/
predicate func_6(EmptyStmt target_10, Function func) {
exists(EmptyStmt target_6 |
	func.getEntryPoint().(BlockStmt).getAStmt()=target_6
	and target_6.getLocation().isBefore(target_10.getLocation())
)
}

predicate func_7(Parameter vsignal_758, ArrayExpr target_7) {
	exists(PointerFieldAccess obj_0 | obj_0=target_7.getArrayBase() |
		obj_0.getTarget().getName()="theData"
		and obj_0.getQualifier().(VariableAccess).getTarget()=vsignal_758
	)
	and target_7.getArrayOffset().(Literal).getValue()="1"
	and target_7.getParent().(FunctionCall).getParent().(ExprStmt).getExpr() instanceof FunctionCall
}

predicate func_8(Function func, ThisExpr target_8) {
	target_8.getType() instanceof PointerType
	and target_8.getEnclosingFunction() = func
}

predicate func_9(Variable vtreeNodePtr_773, VariableAccess target_9) {
	target_9.getTarget()=vtreeNodePtr_773
	and target_9.getParent().(FunctionCall).getParent().(ExprStmt).getExpr() instanceof FunctionCall
}

predicate func_10(Function func, EmptyStmt target_10) {
	func.getEntryPoint().(BlockStmt).getAStmt()=target_10
}

predicate func_11(Function func, ExprStmt target_11) {
	target_11.getExpr() instanceof FunctionCall
	and target_11.getEnclosingFunction() = func
}

predicate func_12(Variable vtreeNodePtr_773, PointerFieldAccess target_12) {
	exists(ValueFieldAccess obj_0 | obj_0=target_12.getQualifier() |
		obj_0.getTarget().getName()="p"
		and obj_0.getQualifier().(VariableAccess).getTarget()=vtreeNodePtr_773
	)
	and target_12.getTarget().getName()="m_requestPtrI"
}

from Function func, Parameter vsignal_758, Variable vtreeNodePtr_773, FunctionCall target_0, ArrayExpr target_7, ThisExpr target_8, VariableAccess target_9, EmptyStmt target_10, ExprStmt target_11, PointerFieldAccess target_12
where
func_0(vtreeNodePtr_773, target_0)
and not func_1(vtreeNodePtr_773, target_11, target_12)
and not func_6(target_10, func)
and func_7(vsignal_758, target_7)
and func_8(func, target_8)
and func_9(vtreeNodePtr_773, target_9)
and func_10(func, target_10)
and func_11(func, target_11)
and func_12(vtreeNodePtr_773, target_12)
and vsignal_758.getType().hasName("Signal *")
and vtreeNodePtr_773.getType().hasName("Ptr<TreeNode>")
and vsignal_758.getFunction() = func
and vtreeNodePtr_773.(LocalVariable).getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
