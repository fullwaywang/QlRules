/**
 * @name wavpack-36a24c7881427d2e1e4dc1cef58f19eee0d13aec-ParseDsdiffHeaderConfig
 * @id cpp/wavpack/36a24c7881427d2e1e4dc1cef58f19eee0d13aec/ParseDsdiffHeaderConfig
 * @description wavpack-36a24c7881427d2e1e4dc1cef58f19eee0d13aec-cli/dsdiff.c-ParseDsdiffHeaderConfig CVE-2018-7253
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vdff_chunk_header_84, Parameter vinfilename_80, NotExpr target_5, ValueFieldAccess target_6, ExprStmt target_7, ExprStmt target_8) {
	exists(IfStmt target_0 |
		target_0.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(ValueFieldAccess).getTarget().getName()="ckDataSize"
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vdff_chunk_header_84
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(Literal).getValue()="4"
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(ValueFieldAccess).getTarget().getName()="ckDataSize"
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vdff_chunk_header_84
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="1024"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("error_line")
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(StringLiteral).getValue()="%s is not a valid .DFF file!"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vinfilename_80
		and target_0.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(Literal).getValue()="1"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_5
		and target_6.getQualifier().(VariableAccess).getLocation().isBefore(target_0.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_7.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation())
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_8.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation()))
}

predicate func_1(Variable vdff_chunk_header_84, Variable vdebug_logging_mode, NotExpr target_5, ValueFieldAccess target_9, IfStmt target_10, IfStmt target_11) {
	exists(IfStmt target_1 |
		target_1.getCondition().(VariableAccess).getTarget()=vdebug_logging_mode
		and target_1.getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("error_line")
		and target_1.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(StringLiteral).getValue()="got PROP chunk of %d bytes total"
		and target_1.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(ValueFieldAccess).getTarget().getName()="ckDataSize"
		and target_1.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vdff_chunk_header_84
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(2)=target_1
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_5
		and target_1.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(ValueFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_9.getQualifier().(VariableAccess).getLocation())
		and target_10.getCondition().(VariableAccess).getLocation().isBefore(target_1.getCondition().(VariableAccess).getLocation())
		and target_1.getCondition().(VariableAccess).getLocation().isBefore(target_11.getCondition().(VariableAccess).getLocation()))
}

predicate func_2(Variable vprop_chunk_156, NotExpr target_5, LogicalOrExpr target_12) {
	exists(ExprStmt target_2 |
		target_2.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vprop_chunk_156
		and target_2.getExpr().(AssignExpr).getRValue() instanceof FunctionCall
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(3)=target_2
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_5
		and target_2.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_12.getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(1).(VariableAccess).getLocation()))
}

predicate func_3(Variable vdff_chunk_header_84, FunctionCall target_3) {
		target_3.getTarget().hasName("malloc")
		and target_3.getArgument(0).(ValueFieldAccess).getTarget().getName()="ckDataSize"
		and target_3.getArgument(0).(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vdff_chunk_header_84
}

predicate func_4(Function func, Initializer target_4) {
		target_4.getExpr() instanceof FunctionCall
		and target_4.getExpr().getEnclosingFunction() = func
}

predicate func_5(Variable vdff_chunk_header_84, NotExpr target_5) {
		target_5.getOperand().(FunctionCall).getTarget().hasName("strncmp")
		and target_5.getOperand().(FunctionCall).getArgument(0).(ValueFieldAccess).getTarget().getName()="ckID"
		and target_5.getOperand().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vdff_chunk_header_84
		and target_5.getOperand().(FunctionCall).getArgument(1).(StringLiteral).getValue()="PROP"
		and target_5.getOperand().(FunctionCall).getArgument(2).(Literal).getValue()="4"
}

predicate func_6(Variable vdff_chunk_header_84, ValueFieldAccess target_6) {
		target_6.getTarget().getName()="ckDataSize"
		and target_6.getQualifier().(VariableAccess).getTarget()=vdff_chunk_header_84
}

predicate func_7(Parameter vinfilename_80, ExprStmt target_7) {
		target_7.getExpr().(FunctionCall).getTarget().hasName("error_line")
		and target_7.getExpr().(FunctionCall).getArgument(0).(StringLiteral).getValue()="%s is not a valid .DFF file!"
		and target_7.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vinfilename_80
}

predicate func_8(Parameter vinfilename_80, ExprStmt target_8) {
		target_8.getExpr().(FunctionCall).getTarget().hasName("error_line")
		and target_8.getExpr().(FunctionCall).getArgument(0).(StringLiteral).getValue()="%s is not a valid .DFF file!"
		and target_8.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vinfilename_80
}

predicate func_9(Variable vdff_chunk_header_84, ValueFieldAccess target_9) {
		target_9.getTarget().getName()="ckDataSize"
		and target_9.getQualifier().(VariableAccess).getTarget()=vdff_chunk_header_84
}

predicate func_10(Variable vdebug_logging_mode, IfStmt target_10) {
		target_10.getCondition().(VariableAccess).getTarget()=vdebug_logging_mode
		and target_10.getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("error_line")
		and target_10.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(StringLiteral).getValue()="dsdiff file version = 0x%08x"
}

predicate func_11(Variable vdebug_logging_mode, IfStmt target_11) {
		target_11.getCondition().(VariableAccess).getTarget()=vdebug_logging_mode
		and target_11.getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("error_line")
		and target_11.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(StringLiteral).getValue()="got sample rate of %u Hz"
}

predicate func_12(Variable vdff_chunk_header_84, Variable vprop_chunk_156, LogicalOrExpr target_12) {
		target_12.getAnOperand().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("DoReadFile")
		and target_12.getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vprop_chunk_156
		and target_12.getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(2).(ValueFieldAccess).getTarget().getName()="ckDataSize"
		and target_12.getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(2).(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vdff_chunk_header_84
		and target_12.getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getTarget().getName()="ckDataSize"
		and target_12.getAnOperand().(EqualityOperation).getAnOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vdff_chunk_header_84
}

from Function func, Variable vdff_chunk_header_84, Variable vdebug_logging_mode, Variable vprop_chunk_156, Parameter vinfilename_80, FunctionCall target_3, Initializer target_4, NotExpr target_5, ValueFieldAccess target_6, ExprStmt target_7, ExprStmt target_8, ValueFieldAccess target_9, IfStmt target_10, IfStmt target_11, LogicalOrExpr target_12
where
not func_0(vdff_chunk_header_84, vinfilename_80, target_5, target_6, target_7, target_8)
and not func_1(vdff_chunk_header_84, vdebug_logging_mode, target_5, target_9, target_10, target_11)
and not func_2(vprop_chunk_156, target_5, target_12)
and func_3(vdff_chunk_header_84, target_3)
and func_4(func, target_4)
and func_5(vdff_chunk_header_84, target_5)
and func_6(vdff_chunk_header_84, target_6)
and func_7(vinfilename_80, target_7)
and func_8(vinfilename_80, target_8)
and func_9(vdff_chunk_header_84, target_9)
and func_10(vdebug_logging_mode, target_10)
and func_11(vdebug_logging_mode, target_11)
and func_12(vdff_chunk_header_84, vprop_chunk_156, target_12)
and vdff_chunk_header_84.getType().hasName("DFFChunkHeader")
and vdebug_logging_mode.getType().hasName("int")
and vprop_chunk_156.getType().hasName("char *")
and vinfilename_80.getType().hasName("char *")
and vdff_chunk_header_84.getParentScope+() = func
and not vdebug_logging_mode.getParentScope+() = func
and vprop_chunk_156.getParentScope+() = func
and vinfilename_80.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
