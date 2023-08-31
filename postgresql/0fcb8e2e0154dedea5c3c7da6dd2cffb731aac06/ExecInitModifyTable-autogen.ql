/**
 * @name postgresql-0fcb8e2e0154dedea5c3c7da6dd2cffb731aac06-ExecInitModifyTable
 * @id cpp/postgresql/0fcb8e2e0154dedea5c3c7da6dd2cffb731aac06/ExecInitModifyTable
 * @description postgresql-0fcb8e2e0154dedea5c3c7da6dd2cffb731aac06-src/backend/executor/nodeModifyTable.c-ExecInitModifyTable CVE-2021-32028
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func, SizeofTypeOperator target_0) {
		target_0.getType() instanceof LongType
		and target_0.getValue()="256"
		and target_0.getEnclosingFunction() = func
}

predicate func_1(Function func, SizeofTypeOperator target_1) {
		target_1.getType() instanceof LongType
		and target_1.getValue()="256"
		and target_1.getEnclosingFunction() = func
}

predicate func_2(Function func, SizeofTypeOperator target_2) {
		target_2.getType() instanceof LongType
		and target_2.getValue()="256"
		and target_2.getEnclosingFunction() = func
}

predicate func_3(Function func, SizeofTypeOperator target_3) {
		target_3.getType() instanceof LongType
		and target_3.getValue()="256"
		and target_3.getEnclosingFunction() = func
}

predicate func_4(Variable vresultRelInfo_1564, PointerFieldAccess target_4) {
		target_4.getTarget().getName()="relhasoids"
		and target_4.getQualifier().(PointerFieldAccess).getTarget().getName()="rd_rel"
		and target_4.getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="ri_RelationDesc"
		and target_4.getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vresultRelInfo_1564
}

predicate func_6(Parameter vnode_1558, Variable vresultRelInfo_1564, PointerFieldAccess target_17) {
	exists(FunctionCall target_6 |
		target_6.getTarget().hasName("ExecCheckPlanOutput")
		and target_6.getArgument(0).(PointerFieldAccess).getTarget().getName()="ri_RelationDesc"
		and target_6.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vresultRelInfo_1564
		and target_6.getArgument(1).(PointerFieldAccess).getTarget().getName()="onConflictSet"
		and target_6.getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vnode_1558
		and target_17.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_6.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_7(Parameter vnode_1558, Variable vmtstate_1560, Variable vresultRelInfo_1564, Variable vecontext_1745, Variable vsetexpr_1746, Variable vtupDesc_1747, EqualityOperation target_18, ExprStmt target_20, ExprStmt target_21, AddressOfExpr target_22, ExprStmt target_23, ExprStmt target_14) {
	exists(IfStmt target_7 |
		target_7.getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getTarget().hasName("ExecCleanTargetListLength")
		and target_7.getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="onConflictSet"
		and target_7.getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vnode_1558
		and target_7.getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getTarget().hasName("list_length")
		and target_7.getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="onConflictSet"
		and target_7.getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vnode_1558
		and target_7.getThen().(BlockStmt).getStmt(0) instanceof ExprStmt
		and target_7.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="mt_confljunk"
		and target_7.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmtstate_1560
		and target_7.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_7.getElse().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getType().hasName("TupleTableSlot *")
		and target_7.getElse().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("ExecInitExtraTupleSlot")
		and target_7.getElse().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(ValueFieldAccess).getTarget().getName()="state"
		and target_7.getElse().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="ps"
		and target_7.getElse().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ExecSetSlotDescriptor")
		and target_7.getElse().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getType().hasName("TupleTableSlot *")
		and target_7.getElse().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vtupDesc_1747
		and target_7.getElse().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="ri_onConflictSetProj"
		and target_7.getElse().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vresultRelInfo_1564
		and target_7.getElse().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("ExecBuildProjectionInfo")
		and target_7.getElse().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsetexpr_1746
		and target_7.getElse().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vecontext_1745
		and target_7.getElse().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getType().hasName("TupleTableSlot *")
		and target_7.getElse().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(PointerFieldAccess).getTarget().getName()="rd_att"
		and target_7.getElse().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="ri_RelationDesc"
		and target_7.getElse().(BlockStmt).getStmt(5).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="mt_confljunk"
		and target_7.getElse().(BlockStmt).getStmt(5).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmtstate_1560
		and target_7.getElse().(BlockStmt).getStmt(5).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("ExecInitJunkFilter")
		and target_7.getElse().(BlockStmt).getStmt(5).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="onConflictSet"
		and target_7.getElse().(BlockStmt).getStmt(5).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vnode_1558
		and target_7.getElse().(BlockStmt).getStmt(5).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="tdhasoid"
		and target_7.getElse().(BlockStmt).getStmt(5).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="rd_att"
		and target_7.getElse().(BlockStmt).getStmt(5).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="mt_conflproj"
		and target_7.getElse().(BlockStmt).getStmt(5).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmtstate_1560
		and target_7.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(12)=target_7
		and target_7.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_18
		and target_7.getCondition().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_20.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_21.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_7.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_7.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_22.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_23.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_7.getElse().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getLocation())
		and target_7.getElse().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_14.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getLocation()))
}

predicate func_8(Parameter vnode_1558, ExprStmt target_25) {
	exists(Initializer target_8 |
		target_8.getExpr().(FunctionCall).getTarget().hasName("ExecTypeFromTL")
		and target_8.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="onConflictSet"
		and target_8.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vnode_1558
		and target_8.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and target_25.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_8.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

/*predicate func_9(Parameter vnode_1558, ExprStmt target_25) {
	exists(PointerFieldAccess target_9 |
		target_9.getTarget().getName()="onConflictSet"
		and target_9.getQualifier().(VariableAccess).getTarget()=vnode_1558
		and target_25.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_9.getQualifier().(VariableAccess).getLocation()))
}

*/
/*predicate func_11(Variable vresultRelInfo_1564, PointerFieldAccess target_28, PointerFieldAccess target_17) {
	exists(PointerFieldAccess target_11 |
		target_11.getTarget().getName()="rd_att"
		and target_11.getQualifier().(PointerFieldAccess).getTarget().getName()="ri_RelationDesc"
		and target_11.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vresultRelInfo_1564
		and target_28.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_11.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_11.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_17.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

*/
predicate func_12(Parameter vnode_1558, Variable vresultRelInfo_1564, PointerFieldAccess target_12) {
		target_12.getTarget().getName()="ri_RelationDesc"
		and target_12.getQualifier().(VariableAccess).getTarget()=vresultRelInfo_1564
		and target_12.getParent().(PointerFieldAccess).getParent().(PointerFieldAccess).getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("ExecTypeFromTL")
		and target_12.getParent().(PointerFieldAccess).getParent().(PointerFieldAccess).getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="onConflictSet"
		and target_12.getParent().(PointerFieldAccess).getParent().(PointerFieldAccess).getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vnode_1558
		and target_12.getParent().(PointerFieldAccess).getParent().(PointerFieldAccess).getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="relhasoids"
		and target_12.getParent().(PointerFieldAccess).getParent().(PointerFieldAccess).getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="rd_rel"
}

/*predicate func_13(Parameter vnode_1558, Variable vresultRelInfo_1564, PointerFieldAccess target_13) {
		target_13.getTarget().getName()="onConflictSet"
		and target_13.getQualifier().(VariableAccess).getTarget()=vnode_1558
		and target_13.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("ExecTypeFromTL")
		and target_13.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="relhasoids"
		and target_13.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="rd_rel"
		and target_13.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="ri_RelationDesc"
		and target_13.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vresultRelInfo_1564
}

*/
predicate func_14(Variable vmtstate_1560, Variable vresultRelInfo_1564, Variable vecontext_1745, Variable vsetexpr_1746, EqualityOperation target_18, ExprStmt target_14) {
		target_14.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="ri_onConflictSetProj"
		and target_14.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vresultRelInfo_1564
		and target_14.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("ExecBuildProjectionInfo")
		and target_14.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsetexpr_1746
		and target_14.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vecontext_1745
		and target_14.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="mt_conflproj"
		and target_14.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmtstate_1560
		and target_14.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(PointerFieldAccess).getTarget().getName()="rd_att"
		and target_14.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="ri_RelationDesc"
		and target_14.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vresultRelInfo_1564
		and target_14.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_18
}

predicate func_15(Variable vmtstate_1560, Variable vtupDesc_1747, VariableAccess target_15) {
		target_15.getTarget()=vtupDesc_1747
		and target_15.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ExecSetSlotDescriptor")
		and target_15.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="mt_conflproj"
		and target_15.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmtstate_1560
}

predicate func_16(Parameter vnode_1558, Variable vresultRelInfo_1564, Variable vtupDesc_1747, AssignExpr target_16) {
		target_16.getLValue().(VariableAccess).getTarget()=vtupDesc_1747
		and target_16.getRValue().(FunctionCall).getTarget().hasName("ExecTypeFromTL")
		and target_16.getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="onConflictSet"
		and target_16.getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vnode_1558
		and target_16.getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="relhasoids"
		and target_16.getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="rd_rel"
		and target_16.getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="ri_RelationDesc"
		and target_16.getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vresultRelInfo_1564
}

predicate func_17(Variable vresultRelInfo_1564, PointerFieldAccess target_17) {
		target_17.getTarget().getName()="rd_rel"
		and target_17.getQualifier().(PointerFieldAccess).getTarget().getName()="ri_RelationDesc"
		and target_17.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vresultRelInfo_1564
}

predicate func_18(Parameter vnode_1558, EqualityOperation target_18) {
		target_18.getAnOperand().(PointerFieldAccess).getTarget().getName()="onConflictAction"
		and target_18.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vnode_1558
}

predicate func_20(Parameter vnode_1558, Variable vmtstate_1560, Variable vsetexpr_1746, ExprStmt target_20) {
		target_20.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vsetexpr_1746
		and target_20.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("ExecInitExpr")
		and target_20.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="onConflictSet"
		and target_20.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vnode_1558
		and target_20.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="ps"
		and target_20.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmtstate_1560
}

predicate func_21(Variable vmtstate_1560, Variable vtupDesc_1747, ExprStmt target_21) {
		target_21.getExpr().(FunctionCall).getTarget().hasName("ExecSetSlotDescriptor")
		and target_21.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="mt_conflproj"
		and target_21.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmtstate_1560
		and target_21.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vtupDesc_1747
}

predicate func_22(Variable vmtstate_1560, AddressOfExpr target_22) {
		target_22.getOperand().(PointerFieldAccess).getTarget().getName()="ps"
		and target_22.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmtstate_1560
}

predicate func_23(Variable vmtstate_1560, Variable vecontext_1745, ExprStmt target_23) {
		target_23.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vecontext_1745
		and target_23.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getTarget().getName()="ps_ExprContext"
		and target_23.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="ps"
		and target_23.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmtstate_1560
}

predicate func_25(Parameter vnode_1558, Variable vmtstate_1560, ExprStmt target_25) {
		target_25.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="mt_excludedtlist"
		and target_25.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmtstate_1560
		and target_25.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="exclRelTlist"
		and target_25.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vnode_1558
}

predicate func_28(Variable vresultRelInfo_1564, PointerFieldAccess target_28) {
		target_28.getTarget().getName()="rd_att"
		and target_28.getQualifier().(PointerFieldAccess).getTarget().getName()="ri_RelationDesc"
		and target_28.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vresultRelInfo_1564
}

from Function func, Parameter vnode_1558, Variable vmtstate_1560, Variable vresultRelInfo_1564, Variable vecontext_1745, Variable vsetexpr_1746, Variable vtupDesc_1747, SizeofTypeOperator target_0, SizeofTypeOperator target_1, SizeofTypeOperator target_2, SizeofTypeOperator target_3, PointerFieldAccess target_4, PointerFieldAccess target_12, ExprStmt target_14, VariableAccess target_15, AssignExpr target_16, PointerFieldAccess target_17, EqualityOperation target_18, ExprStmt target_20, ExprStmt target_21, AddressOfExpr target_22, ExprStmt target_23, ExprStmt target_25, PointerFieldAccess target_28
where
func_0(func, target_0)
and func_1(func, target_1)
and func_2(func, target_2)
and func_3(func, target_3)
and func_4(vresultRelInfo_1564, target_4)
and not func_6(vnode_1558, vresultRelInfo_1564, target_17)
and not func_7(vnode_1558, vmtstate_1560, vresultRelInfo_1564, vecontext_1745, vsetexpr_1746, vtupDesc_1747, target_18, target_20, target_21, target_22, target_23, target_14)
and not func_8(vnode_1558, target_25)
and func_12(vnode_1558, vresultRelInfo_1564, target_12)
and func_14(vmtstate_1560, vresultRelInfo_1564, vecontext_1745, vsetexpr_1746, target_18, target_14)
and func_15(vmtstate_1560, vtupDesc_1747, target_15)
and func_16(vnode_1558, vresultRelInfo_1564, vtupDesc_1747, target_16)
and func_17(vresultRelInfo_1564, target_17)
and func_18(vnode_1558, target_18)
and func_20(vnode_1558, vmtstate_1560, vsetexpr_1746, target_20)
and func_21(vmtstate_1560, vtupDesc_1747, target_21)
and func_22(vmtstate_1560, target_22)
and func_23(vmtstate_1560, vecontext_1745, target_23)
and func_25(vnode_1558, vmtstate_1560, target_25)
and func_28(vresultRelInfo_1564, target_28)
and vnode_1558.getType().hasName("ModifyTable *")
and vmtstate_1560.getType().hasName("ModifyTableState *")
and vresultRelInfo_1564.getType().hasName("ResultRelInfo *")
and vecontext_1745.getType().hasName("ExprContext *")
and vsetexpr_1746.getType().hasName("ExprState *")
and vtupDesc_1747.getType().hasName("TupleDesc")
and vnode_1558.getFunction() = func
and vmtstate_1560.(LocalVariable).getFunction() = func
and vresultRelInfo_1564.(LocalVariable).getFunction() = func
and vecontext_1745.(LocalVariable).getFunction() = func
and vsetexpr_1746.(LocalVariable).getFunction() = func
and vtupDesc_1747.(LocalVariable).getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
