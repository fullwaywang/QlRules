/**
 * @name ghostscript-0d3901189f245232f0161addf215d7268c4d05a3-ztempfile
 * @id cpp/ghostscript/0d3901189f245232f0161addf215d7268c4d05a3/ztempfile
 * @description ghostscript-0d3901189f245232f0161addf215d7268c4d05a3-psi/zfile.c-ztempfile CVE-2018-15908
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vpstr_700, BlockStmt target_11, FunctionCall target_12, RelationalOperation target_13) {
	exists(EqualityOperation target_0 |
		target_0.getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vpstr_700
		and target_0.getAnOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getType().hasName("int")
		and target_0.getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getType().hasName("const char *")
		and target_0.getAnOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_0.getParent().(IfStmt).getThen()=target_11
		and target_12.getArgument(0).(VariableAccess).getLocation().isBefore(target_0.getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getLocation())
		and target_0.getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getLocation().isBefore(target_13.getLesserOperand().(FunctionCall).getArgument(1).(VariableAccess).getLocation()))
}

predicate func_1(RelationalOperation target_13, Function func) {
	exists(BreakStmt target_1 |
		target_1.getParent().(IfStmt).getCondition()=target_13
		and target_1.getEnclosingFunction() = func)
}

predicate func_2(Variable vpstr_700, Variable vfname_704, FunctionCall target_14) {
	exists(ExprStmt target_2 |
		target_2.getExpr().(FunctionCall).getTarget().hasName("memcpy")
		and target_2.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vfname_704
		and target_2.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vpstr_700
		and target_2.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getType().hasName("int")
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(3)=target_2
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_14)
}

predicate func_3(Variable vfname_704, FunctionCall target_14, ExprStmt target_15) {
	exists(ExprStmt target_3 |
		target_3.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vfname_704
		and target_3.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(VariableAccess).getType().hasName("int")
		and target_3.getExpr().(AssignExpr).getRValue().(CharLiteral).getValue()="0"
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(4)=target_3
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_14
		and target_3.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getLocation().isBefore(target_15.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getLocation()))
}

predicate func_4(Variable vcode_702, Variable vfname_704, Parameter vi_ctx_p_697, FunctionCall target_14, ExprStmt target_16, LogicalOrExpr target_17, ValueFieldAccess target_18, ValueFieldAccess target_19) {
	exists(IfStmt target_4 |
		target_4.getCondition().(RelationalOperation).getLesserOperand().(FunctionCall).getTarget().hasName("check_file_permissions")
		and target_4.getCondition().(RelationalOperation).getLesserOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vi_ctx_p_697
		and target_4.getCondition().(RelationalOperation).getLesserOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vfname_704
		and target_4.getCondition().(RelationalOperation).getLesserOperand().(FunctionCall).getArgument(2).(FunctionCall).getTarget().hasName("strlen")
		and target_4.getCondition().(RelationalOperation).getLesserOperand().(FunctionCall).getArgument(2).(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vfname_704
		and target_4.getCondition().(RelationalOperation).getLesserOperand().(FunctionCall).getArgument(3).(Literal).getValue()="0"
		and target_4.getCondition().(RelationalOperation).getLesserOperand().(FunctionCall).getArgument(4).(StringLiteral).getValue()="PermitFileWriting"
		and target_4.getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="0"
		and target_4.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vcode_702
		and target_4.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(5)=target_4
		and target_4.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_14
		and target_16.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_4.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation())
		and target_17.getAnOperand().(NotExpr).getOperand().(VariableAccess).getLocation().isBefore(target_4.getCondition().(RelationalOperation).getLesserOperand().(FunctionCall).getArgument(1).(VariableAccess).getLocation())
		and target_18.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_4.getCondition().(RelationalOperation).getLesserOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_4.getCondition().(RelationalOperation).getLesserOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_19.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_8(Variable vpstr_700, Parameter vi_ctx_p_697, FunctionCall target_8) {
		target_8.getTarget().hasName("strlen")
		and target_8.getArgument(0).(VariableAccess).getTarget()=vpstr_700
		and target_8.getParent().(FunctionCall).getParent().(LTExpr).getLesserOperand().(FunctionCall).getTarget().hasName("check_file_permissions")
		and target_8.getParent().(FunctionCall).getParent().(LTExpr).getLesserOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vi_ctx_p_697
		and target_8.getParent().(FunctionCall).getParent().(LTExpr).getLesserOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vpstr_700
		and target_8.getParent().(FunctionCall).getParent().(LTExpr).getLesserOperand().(FunctionCall).getArgument(3).(Literal).getValue()="0"
		and target_8.getParent().(FunctionCall).getParent().(LTExpr).getLesserOperand().(FunctionCall).getArgument(4).(StringLiteral).getValue()="PermitFileWriting"
}

/*predicate func_9(Variable vpstr_700, Parameter vi_ctx_p_697, VariableAccess target_9) {
		target_9.getTarget()=vpstr_700
		and target_9.getParent().(FunctionCall).getParent().(LTExpr).getLesserOperand().(FunctionCall).getTarget().hasName("check_file_permissions")
		and target_9.getParent().(FunctionCall).getParent().(LTExpr).getLesserOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vi_ctx_p_697
		and target_9.getParent().(FunctionCall).getParent().(LTExpr).getLesserOperand().(FunctionCall).getArgument(2).(FunctionCall).getTarget().hasName("strlen")
		and target_9.getParent().(FunctionCall).getParent().(LTExpr).getLesserOperand().(FunctionCall).getArgument(2).(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vpstr_700
		and target_9.getParent().(FunctionCall).getParent().(LTExpr).getLesserOperand().(FunctionCall).getArgument(3).(Literal).getValue()="0"
		and target_9.getParent().(FunctionCall).getParent().(LTExpr).getLesserOperand().(FunctionCall).getArgument(4).(StringLiteral).getValue()="PermitFileWriting"
}

*/
predicate func_10(Function func, LabelStmt target_10) {
		func.getEntryPoint().(BlockStmt).getAStmt()=target_10
}

predicate func_11(Variable vcode_702, BlockStmt target_11) {
		target_11.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vcode_702
}

predicate func_12(Variable vpstr_700, FunctionCall target_12) {
		target_12.getTarget().hasName("strlen")
		and target_12.getArgument(0).(VariableAccess).getTarget()=vpstr_700
}

predicate func_13(Variable vpstr_700, Parameter vi_ctx_p_697, RelationalOperation target_13) {
		 (target_13 instanceof GTExpr or target_13 instanceof LTExpr)
		and target_13.getLesserOperand().(FunctionCall).getTarget().hasName("check_file_permissions")
		and target_13.getLesserOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vi_ctx_p_697
		and target_13.getLesserOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vpstr_700
		and target_13.getLesserOperand().(FunctionCall).getArgument(2) instanceof FunctionCall
		and target_13.getLesserOperand().(FunctionCall).getArgument(3).(Literal).getValue()="0"
		and target_13.getLesserOperand().(FunctionCall).getArgument(4).(StringLiteral).getValue()="PermitFileWriting"
		and target_13.getGreaterOperand().(Literal).getValue()="0"
}

predicate func_14(Variable vpstr_700, FunctionCall target_14) {
		target_14.getTarget().hasName("gp_file_name_is_absolute")
		and target_14.getArgument(0).(VariableAccess).getTarget()=vpstr_700
		and target_14.getArgument(1).(FunctionCall).getTarget().hasName("strlen")
		and target_14.getArgument(1).(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vpstr_700
}

predicate func_15(Variable vpstr_700, Variable vfname_704, Parameter vi_ctx_p_697, ExprStmt target_15) {
		target_15.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("FILE *")
		and target_15.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("gp_open_scratch_file")
		and target_15.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(ValueFieldAccess).getTarget().getName()="current"
		and target_15.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="memory"
		and target_15.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vi_ctx_p_697
		and target_15.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vpstr_700
		and target_15.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vfname_704
		and target_15.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(VariableAccess).getTarget().getType().hasName("char[4]")
}

predicate func_16(Variable vcode_702, ExprStmt target_16) {
		target_16.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vcode_702
}

predicate func_17(Variable vfname_704, LogicalOrExpr target_17) {
		target_17.getAnOperand().(NotExpr).getOperand().(VariableAccess).getTarget().getType().hasName("char *")
		and target_17.getAnOperand().(NotExpr).getOperand().(VariableAccess).getTarget()=vfname_704
}

predicate func_18(Parameter vi_ctx_p_697, ValueFieldAccess target_18) {
		target_18.getTarget().getName()="current"
		and target_18.getQualifier().(PointerFieldAccess).getTarget().getName()="memory"
		and target_18.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vi_ctx_p_697
}

predicate func_19(Parameter vi_ctx_p_697, ValueFieldAccess target_19) {
		target_19.getTarget().getName()="current"
		and target_19.getQualifier().(PointerFieldAccess).getTarget().getName()="memory"
		and target_19.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vi_ctx_p_697
}

from Function func, Variable vpstr_700, Variable vcode_702, Variable vfname_704, Parameter vi_ctx_p_697, FunctionCall target_8, LabelStmt target_10, BlockStmt target_11, FunctionCall target_12, RelationalOperation target_13, FunctionCall target_14, ExprStmt target_15, ExprStmt target_16, LogicalOrExpr target_17, ValueFieldAccess target_18, ValueFieldAccess target_19
where
not func_0(vpstr_700, target_11, target_12, target_13)
and not func_1(target_13, func)
and not func_2(vpstr_700, vfname_704, target_14)
and not func_3(vfname_704, target_14, target_15)
and not func_4(vcode_702, vfname_704, vi_ctx_p_697, target_14, target_16, target_17, target_18, target_19)
and func_8(vpstr_700, vi_ctx_p_697, target_8)
and func_10(func, target_10)
and func_11(vcode_702, target_11)
and func_12(vpstr_700, target_12)
and func_13(vpstr_700, vi_ctx_p_697, target_13)
and func_14(vpstr_700, target_14)
and func_15(vpstr_700, vfname_704, vi_ctx_p_697, target_15)
and func_16(vcode_702, target_16)
and func_17(vfname_704, target_17)
and func_18(vi_ctx_p_697, target_18)
and func_19(vi_ctx_p_697, target_19)
and vpstr_700.getType().hasName("const char *")
and vcode_702.getType().hasName("int")
and vfname_704.getType().hasName("char *")
and vi_ctx_p_697.getType().hasName("i_ctx_t *")
and vpstr_700.(LocalVariable).getFunction() = func
and vcode_702.(LocalVariable).getFunction() = func
and vfname_704.(LocalVariable).getFunction() = func
and vi_ctx_p_697.getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
