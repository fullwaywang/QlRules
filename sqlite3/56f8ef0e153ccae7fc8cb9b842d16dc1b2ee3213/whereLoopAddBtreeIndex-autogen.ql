/**
 * @name sqlite3-56f8ef0e153ccae7fc8cb9b842d16dc1b2ee3213-whereLoopAddBtreeIndex
 * @id cpp/sqlite3/56f8ef0e153ccae7fc8cb9b842d16dc1b2ee3213/whereLoopAddBtreeIndex
 * @description sqlite3-56f8ef0e153ccae7fc8cb9b842d16dc1b2ee3213-src/where.c-whereLoopAddBtreeIndex CVE-2013-7443
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vdb_3870, Variable vpNew_3871, Variable vrc_3882, BlockStmt target_2, IfStmt target_3, FunctionCall target_4, ExprStmt target_5, ValueFieldAccess target_6, LogicalAndExpr target_7) {
	exists(LogicalAndExpr target_0 |
		target_0.getAnOperand() instanceof LogicalAndExpr
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(AssignExpr).getLValue().(VariableAccess).getTarget()=vrc_3882
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("whereLoopResize")
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vdb_3870
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vpNew_3871
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(AddExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="nLTerm"
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(AddExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpNew_3871
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(AddExpr).getAnOperand().(Literal).getValue()="1"
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_0.getParent().(IfStmt).getThen()=target_2
		and target_3.getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getAnOperand().(EqualityOperation).getAnOperand().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_4.getArgument(0).(VariableAccess).getLocation())
		and target_5.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getAnOperand().(EqualityOperation).getAnOperand().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getLocation())
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_6.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_7.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vpProbe_3865, Variable vpTerm_3872, Variable vsaved_nEq_3877, Variable vsaved_nSkip_3878, BlockStmt target_2, LogicalAndExpr target_1) {
		target_1.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vpTerm_3872
		and target_1.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_1.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vsaved_nEq_3877
		and target_1.getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vsaved_nSkip_3878
		and target_1.getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vsaved_nEq_3877
		and target_1.getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(AddExpr).getAnOperand().(Literal).getValue()="1"
		and target_1.getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="nKeyCol"
		and target_1.getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpProbe_3865
		and target_1.getAnOperand().(RelationalOperation).getGreaterOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="aiRowEst"
		and target_1.getAnOperand().(RelationalOperation).getGreaterOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpProbe_3865
		and target_1.getAnOperand().(RelationalOperation).getGreaterOperand().(ArrayExpr).getArrayOffset().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vsaved_nEq_3877
		and target_1.getAnOperand().(RelationalOperation).getGreaterOperand().(ArrayExpr).getArrayOffset().(AddExpr).getAnOperand().(Literal).getValue()="1"
		and target_1.getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="18"
		and target_1.getParent().(IfStmt).getThen()=target_2
}

predicate func_2(Variable vpNew_3871, BlockStmt target_2) {
		target_2.getStmt(1).(ExprStmt).getExpr().(PostfixIncrExpr).getOperand().(ValueFieldAccess).getTarget().getName()="nEq"
		and target_2.getStmt(1).(ExprStmt).getExpr().(PostfixIncrExpr).getOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="btree"
		and target_2.getStmt(1).(ExprStmt).getExpr().(PostfixIncrExpr).getOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="u"
		and target_2.getStmt(1).(ExprStmt).getExpr().(PostfixIncrExpr).getOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpNew_3871
		and target_2.getStmt(2).(ExprStmt).getExpr().(PostfixIncrExpr).getOperand().(ValueFieldAccess).getTarget().getName()="nSkip"
		and target_2.getStmt(2).(ExprStmt).getExpr().(PostfixIncrExpr).getOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="btree"
		and target_2.getStmt(2).(ExprStmt).getExpr().(PostfixIncrExpr).getOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="u"
		and target_2.getStmt(2).(ExprStmt).getExpr().(PostfixIncrExpr).getOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpNew_3871
}

predicate func_3(Variable vdb_3870, IfStmt target_3) {
		target_3.getCondition().(PointerFieldAccess).getTarget().getName()="mallocFailed"
		and target_3.getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdb_3870
		and target_3.getThen().(ReturnStmt).getExpr().(Literal).getValue()="7"
}

predicate func_4(Variable vdb_3870, Variable vpNew_3871, FunctionCall target_4) {
		target_4.getTarget().hasName("whereLoopResize")
		and target_4.getArgument(0).(VariableAccess).getTarget()=vdb_3870
		and target_4.getArgument(1).(VariableAccess).getTarget()=vpNew_3871
		and target_4.getArgument(2).(AddExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="nLTerm"
		and target_4.getArgument(2).(AddExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpNew_3871
		and target_4.getArgument(2).(AddExpr).getAnOperand().(Literal).getValue()="1"
}

predicate func_5(Variable vpNew_3871, ExprStmt target_5) {
		target_5.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="rSetup"
		and target_5.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpNew_3871
		and target_5.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
}

predicate func_6(Variable vpNew_3871, ValueFieldAccess target_6) {
		target_6.getTarget().getName()="btree"
		and target_6.getQualifier().(PointerFieldAccess).getTarget().getName()="u"
		and target_6.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpNew_3871
}

predicate func_7(Variable vpTerm_3872, Variable vrc_3882, LogicalAndExpr target_7) {
		target_7.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vrc_3882
		and target_7.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_7.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vpTerm_3872
		and target_7.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
}

from Function func, Parameter vpProbe_3865, Variable vdb_3870, Variable vpNew_3871, Variable vpTerm_3872, Variable vsaved_nEq_3877, Variable vsaved_nSkip_3878, Variable vrc_3882, LogicalAndExpr target_1, BlockStmt target_2, IfStmt target_3, FunctionCall target_4, ExprStmt target_5, ValueFieldAccess target_6, LogicalAndExpr target_7
where
not func_0(vdb_3870, vpNew_3871, vrc_3882, target_2, target_3, target_4, target_5, target_6, target_7)
and func_1(vpProbe_3865, vpTerm_3872, vsaved_nEq_3877, vsaved_nSkip_3878, target_2, target_1)
and func_2(vpNew_3871, target_2)
and func_3(vdb_3870, target_3)
and func_4(vdb_3870, vpNew_3871, target_4)
and func_5(vpNew_3871, target_5)
and func_6(vpNew_3871, target_6)
and func_7(vpTerm_3872, vrc_3882, target_7)
and vpProbe_3865.getType().hasName("Index *")
and vdb_3870.getType().hasName("sqlite3 *")
and vpNew_3871.getType().hasName("WhereLoop *")
and vpTerm_3872.getType().hasName("WhereTerm *")
and vsaved_nEq_3877.getType().hasName("u16")
and vsaved_nSkip_3878.getType().hasName("u16")
and vrc_3882.getType().hasName("int")
and vpProbe_3865.getFunction() = func
and vdb_3870.(LocalVariable).getFunction() = func
and vpNew_3871.(LocalVariable).getFunction() = func
and vpTerm_3872.(LocalVariable).getFunction() = func
and vsaved_nEq_3877.(LocalVariable).getFunction() = func
and vsaved_nSkip_3878.(LocalVariable).getFunction() = func
and vrc_3882.(LocalVariable).getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
