/**
 * @name postgresql-b8a1247a34e234be6becf7f70b9f1e8e9369db64-transformOnConflictClause
 * @id cpp/postgresql/b8a1247a34e234be6becf7f70b9f1e8e9369db64/transformOnConflictClause
 * @description postgresql-b8a1247a34e234be6becf7f70b9f1e8e9369db64-src/backend/parser/analyze.c-transformOnConflictClause CVE-2018-10925
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vexclRelTlist_1014, Variable vte_1026, FunctionCall target_0) {
		target_0.getTarget().hasName("lappend")
		and not target_0.getTarget().hasName("BuildOnConflictExcludedTargetlist")
		and target_0.getArgument(0).(VariableAccess).getTarget()=vexclRelTlist_1014
		and target_0.getArgument(1).(VariableAccess).getTarget()=vte_1026
		and target_0.getParent().(AssignExpr).getRValue() = target_0
		and target_0.getParent().(AssignExpr).getLValue().(VariableAccess).getTarget()=vexclRelTlist_1014
}

predicate func_1(Variable vexclRte_1012, ExprStmt target_20, ExprStmt target_21) {
	exists(AssignExpr target_1 |
		target_1.getLValue().(PointerFieldAccess).getTarget().getName()="requiredPerms"
		and target_1.getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vexclRte_1012
		and target_1.getRValue() instanceof Literal
		and target_20.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_1.getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_1.getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_21.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation()))
}

predicate func_3(Variable vtargetrel_1024, VariableAccess target_3) {
		target_3.getTarget()=vtargetrel_1024
}

predicate func_4(Variable vexclRelIndex_1013, VariableAccess target_4) {
		target_4.getTarget()=vexclRelIndex_1013
		and target_4.getParent().(FunctionCall).getParent().(AssignExpr).getRValue() instanceof FunctionCall
}

predicate func_5(EqualityOperation target_22, Function func, DeclStmt target_5) {
		target_5.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_22
		and target_5.getEnclosingFunction() = func
}

predicate func_6(EqualityOperation target_22, Function func, DeclStmt target_6) {
		target_6.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_22
		and target_6.getEnclosingFunction() = func
}

predicate func_7(EqualityOperation target_22, Function func, DeclStmt target_7) {
		target_7.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_22
		and target_7.getEnclosingFunction() = func
}

predicate func_8(Variable vexclRelTlist_1014, Variable vtargetrel_1024, Variable vvar_1025, Variable vte_1026, Variable vattno_1027, Variable vattr_1054, Variable vname_1055, EqualityOperation target_22, ForStmt target_8) {
		target_8.getInitialization().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vattno_1027
		and target_8.getInitialization().(ExprStmt).getExpr().(AssignExpr).getRValue() instanceof Literal
		and target_8.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vattno_1027
		and target_8.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="relnatts"
		and target_8.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="rd_rel"
		and target_8.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtargetrel_1024
		and target_8.getUpdate().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vattno_1027
		and target_8.getStmt().(BlockStmt).getStmt(2).(IfStmt).getCondition().(PointerFieldAccess).getTarget().getName()="attisdropped"
		and target_8.getStmt().(BlockStmt).getStmt(2).(IfStmt).getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vattr_1054
		and target_8.getStmt().(BlockStmt).getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vvar_1025
		and target_8.getStmt().(BlockStmt).getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("makeNullConst")
		and target_8.getStmt().(BlockStmt).getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vname_1055
		and target_8.getStmt().(BlockStmt).getStmt(2).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(StringLiteral).getValue()=""
		and target_8.getStmt().(BlockStmt).getStmt(2).(IfStmt).getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vvar_1025
		and target_8.getStmt().(BlockStmt).getStmt(2).(IfStmt).getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("makeVar")
		and target_8.getStmt().(BlockStmt).getStmt(2).(IfStmt).getElse().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vname_1055
		and target_8.getStmt().(BlockStmt).getStmt(2).(IfStmt).getElse().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("pstrdup")
		and target_8.getStmt().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vte_1026
		and target_8.getStmt().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("makeTargetEntry")
		and target_8.getStmt().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vvar_1025
		and target_8.getStmt().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(AddExpr).getAnOperand().(VariableAccess).getTarget()=vattno_1027
		and target_8.getStmt().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(AddExpr).getAnOperand().(Literal).getValue()="1"
		and target_8.getStmt().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vname_1055
		and target_8.getStmt().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(Literal).getValue()="0"
		and target_8.getStmt().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vexclRelTlist_1014
		and target_8.getStmt().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(AssignExpr).getRValue() instanceof FunctionCall
		and target_8.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_22
}

/*predicate func_11(Variable vexclRelIndex_1013, Variable vvar_1025, Variable vattno_1027, Variable vattr_1054, Variable vname_1055, IfStmt target_11) {
		target_11.getCondition().(PointerFieldAccess).getTarget().getName()="attisdropped"
		and target_11.getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vattr_1054
		and target_11.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vvar_1025
		and target_11.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("makeNullConst")
		and target_11.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(Literal).getValue()="23"
		and target_11.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(UnaryMinusExpr).getValue()="-1"
		and target_11.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(Literal).getValue()="0"
		and target_11.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vname_1055
		and target_11.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(StringLiteral).getValue()=""
		and target_11.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vvar_1025
		and target_11.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("makeVar")
		and target_11.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vexclRelIndex_1013
		and target_11.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(AddExpr).getAnOperand().(VariableAccess).getTarget()=vattno_1027
		and target_11.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(AddExpr).getAnOperand().(Literal).getValue()="1"
		and target_11.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="atttypid"
		and target_11.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vattr_1054
		and target_11.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(PointerFieldAccess).getTarget().getName()="atttypmod"
		and target_11.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vattr_1054
		and target_11.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(4).(PointerFieldAccess).getTarget().getName()="attcollation"
		and target_11.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(4).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vattr_1054
		and target_11.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(5).(Literal).getValue()="0"
		and target_11.getElse().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vname_1055
		and target_11.getElse().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("pstrdup")
		and target_11.getElse().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(ValueFieldAccess).getTarget().getName()="data"
		and target_11.getElse().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="attname"
}

*/
/*predicate func_12(Variable vvar_1025, PointerFieldAccess target_23, ExprStmt target_12) {
		target_12.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vvar_1025
		and target_12.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("makeNullConst")
		and target_12.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(Literal).getValue()="23"
		and target_12.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(UnaryMinusExpr).getValue()="-1"
		and target_12.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(Literal).getValue()="0"
		and target_12.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_23
}

*/
/*predicate func_13(Variable vname_1055, PointerFieldAccess target_23, ExprStmt target_13) {
		target_13.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vname_1055
		and target_13.getExpr().(AssignExpr).getRValue().(StringLiteral).getValue()=""
		and target_13.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_23
}

*/
/*predicate func_14(Variable vexclRelIndex_1013, Variable vvar_1025, Variable vattno_1027, Variable vattr_1054, PointerFieldAccess target_23, ExprStmt target_14) {
		target_14.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vvar_1025
		and target_14.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("makeVar")
		and target_14.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vexclRelIndex_1013
		and target_14.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(AddExpr).getAnOperand().(VariableAccess).getTarget()=vattno_1027
		and target_14.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(AddExpr).getAnOperand().(Literal).getValue()="1"
		and target_14.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="atttypid"
		and target_14.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vattr_1054
		and target_14.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(PointerFieldAccess).getTarget().getName()="atttypmod"
		and target_14.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vattr_1054
		and target_14.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(4).(PointerFieldAccess).getTarget().getName()="attcollation"
		and target_14.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(4).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vattr_1054
		and target_14.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(5).(Literal).getValue()="0"
		and target_14.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_23
}

*/
/*predicate func_15(Variable vattr_1054, Variable vname_1055, PointerFieldAccess target_23, ExprStmt target_15) {
		target_15.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vname_1055
		and target_15.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("pstrdup")
		and target_15.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(ValueFieldAccess).getTarget().getName()="data"
		and target_15.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="attname"
		and target_15.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vattr_1054
		and target_15.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_23
}

*/
/*predicate func_16(Variable vvar_1025, Variable vte_1026, Variable vattno_1027, Variable vname_1055, ExprStmt target_16) {
		target_16.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vte_1026
		and target_16.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("makeTargetEntry")
		and target_16.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vvar_1025
		and target_16.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(AddExpr).getAnOperand().(VariableAccess).getTarget()=vattno_1027
		and target_16.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(AddExpr).getAnOperand().(Literal).getValue()="1"
		and target_16.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vname_1055
		and target_16.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(Literal).getValue()="0"
}

*/
predicate func_17(Variable vexclRelIndex_1013, Variable vtargetrel_1024, Variable vvar_1025, AssignExpr target_17) {
		target_17.getLValue().(VariableAccess).getTarget()=vvar_1025
		and target_17.getRValue().(FunctionCall).getTarget().hasName("makeVar")
		and target_17.getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vexclRelIndex_1013
		and target_17.getRValue().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and target_17.getRValue().(FunctionCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="reltype"
		and target_17.getRValue().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="rd_rel"
		and target_17.getRValue().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtargetrel_1024
		and target_17.getRValue().(FunctionCall).getArgument(3).(UnaryMinusExpr).getValue()="-1"
		and target_17.getRValue().(FunctionCall).getArgument(4).(Literal).getValue()="0"
		and target_17.getRValue().(FunctionCall).getArgument(5).(Literal).getValue()="0"
}

predicate func_18(Variable vvar_1025, Variable vte_1026, EqualityOperation target_22, ExprStmt target_18) {
		target_18.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vte_1026
		and target_18.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("makeTargetEntry")
		and target_18.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vvar_1025
		and target_18.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and target_18.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(Literal).getValue()="0"
		and target_18.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(Literal).getValue()="1"
		and target_18.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_22
}

predicate func_19(Variable vexclRelTlist_1014, Variable vte_1026, EqualityOperation target_22, ExprStmt target_19) {
		target_19.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vexclRelTlist_1014
		and target_19.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("lappend")
		and target_19.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vexclRelTlist_1014
		and target_19.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vte_1026
		and target_19.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_22
}

predicate func_20(Variable vexclRte_1012, ExprStmt target_20) {
		target_20.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="relkind"
		and target_20.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vexclRte_1012
		and target_20.getExpr().(AssignExpr).getRValue().(Literal).getValue()="99"
}

predicate func_21(Variable vexclRte_1012, ExprStmt target_21) {
		target_21.getExpr().(FunctionCall).getTarget().hasName("addRTEtoQuery")
		and target_21.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget().getType().hasName("ParseState *")
		and target_21.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vexclRte_1012
		and target_21.getExpr().(FunctionCall).getArgument(2).(Literal).getValue()="0"
		and target_21.getExpr().(FunctionCall).getArgument(3).(Literal).getValue()="1"
		and target_21.getExpr().(FunctionCall).getArgument(4).(Literal).getValue()="1"
}

predicate func_22(EqualityOperation target_22) {
		target_22.getAnOperand().(PointerFieldAccess).getTarget().getName()="action"
		and target_22.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("OnConflictClause *")
}

predicate func_23(Variable vattr_1054, PointerFieldAccess target_23) {
		target_23.getTarget().getName()="attisdropped"
		and target_23.getQualifier().(VariableAccess).getTarget()=vattr_1054
}

from Function func, Variable vexclRte_1012, Variable vexclRelIndex_1013, Variable vexclRelTlist_1014, Variable vtargetrel_1024, Variable vvar_1025, Variable vte_1026, Variable vattno_1027, Variable vattr_1054, Variable vname_1055, FunctionCall target_0, VariableAccess target_3, VariableAccess target_4, DeclStmt target_5, DeclStmt target_6, DeclStmt target_7, ForStmt target_8, AssignExpr target_17, ExprStmt target_18, ExprStmt target_19, ExprStmt target_20, ExprStmt target_21, EqualityOperation target_22, PointerFieldAccess target_23
where
func_0(vexclRelTlist_1014, vte_1026, target_0)
and not func_1(vexclRte_1012, target_20, target_21)
and func_3(vtargetrel_1024, target_3)
and func_4(vexclRelIndex_1013, target_4)
and func_5(target_22, func, target_5)
and func_6(target_22, func, target_6)
and func_7(target_22, func, target_7)
and func_8(vexclRelTlist_1014, vtargetrel_1024, vvar_1025, vte_1026, vattno_1027, vattr_1054, vname_1055, target_22, target_8)
and func_17(vexclRelIndex_1013, vtargetrel_1024, vvar_1025, target_17)
and func_18(vvar_1025, vte_1026, target_22, target_18)
and func_19(vexclRelTlist_1014, vte_1026, target_22, target_19)
and func_20(vexclRte_1012, target_20)
and func_21(vexclRte_1012, target_21)
and func_22(target_22)
and func_23(vattr_1054, target_23)
and vexclRte_1012.getType().hasName("RangeTblEntry *")
and vexclRelIndex_1013.getType().hasName("int")
and vexclRelTlist_1014.getType().hasName("List *")
and vtargetrel_1024.getType().hasName("Relation")
and vvar_1025.getType().hasName("Var *")
and vte_1026.getType().hasName("TargetEntry *")
and vattno_1027.getType().hasName("int")
and vattr_1054.getType().hasName("Form_pg_attribute")
and vname_1055.getType().hasName("char *")
and vexclRte_1012.(LocalVariable).getFunction() = func
and vexclRelIndex_1013.(LocalVariable).getFunction() = func
and vexclRelTlist_1014.(LocalVariable).getFunction() = func
and vtargetrel_1024.(LocalVariable).getFunction() = func
and vvar_1025.(LocalVariable).getFunction() = func
and vte_1026.(LocalVariable).getFunction() = func
and vattno_1027.(LocalVariable).getFunction() = func
and vattr_1054.(LocalVariable).getFunction() = func
and vname_1055.(LocalVariable).getFunction() = func
select func, "function relativepath is " + func.getFile(), "function startline is " + func.getLocation().getStartLine()
