/**
 * @name wavpack-89df160596132e3bd666322e1c20b2ebd4b92cd0-WavpackSetConfiguration64
 * @id cpp/wavpack/89df160596132e3bd666322e1c20b2ebd4b92cd0/WavpackSetConfiguration64
 * @description wavpack-89df160596132e3bd666322e1c20b2ebd4b92cd0-src/pack_utils.c-WavpackSetConfiguration64 CVE-2020-35738
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func, StringLiteral target_0) {
		target_0.getValue()="channel count cannot be zero!"
		and not target_0.getValue()="invalid channel count!"
		and target_0.getEnclosingFunction() = func
}

predicate func_1(Variable vnum_chans_195, BlockStmt target_4, NotExpr target_3) {
	exists(LogicalOrExpr target_1 |
		target_1.getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vnum_chans_195
		and target_1.getAnOperand().(RelationalOperation).getGreaterOperand().(Literal).getValue()="0"
		and target_1.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vnum_chans_195
		and target_1.getAnOperand().(RelationalOperation).getLesserOperand().(MulExpr).getValue()="8192"
		and target_1.getParent().(IfStmt).getThen()=target_4
		and target_1.getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation().isBefore(target_3.getOperand().(VariableAccess).getLocation()))
}

predicate func_2(Parameter vwpc_191, Parameter vconfig_191, ExprStmt target_5, ExprStmt target_6, RelationalOperation target_7, Function func) {
	exists(IfStmt target_2 |
		target_2.getCondition().(LogicalAndExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="block_samples"
		and target_2.getCondition().(LogicalAndExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconfig_191
		and target_2.getCondition().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getTarget().getName()="block_samples"
		and target_2.getCondition().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconfig_191
		and target_2.getCondition().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(Literal).getValue()="16"
		and target_2.getCondition().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="block_samples"
		and target_2.getCondition().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconfig_191
		and target_2.getCondition().(LogicalAndExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="131072"
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("strcpy")
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="error_message"
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vwpc_191
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="invalid custom block samples!"
		and target_2.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(Literal).getValue()="0"
		and (func.getEntryPoint().(BlockStmt).getStmt(6)=target_2 or func.getEntryPoint().(BlockStmt).getStmt(6).getFollowingStmt()=target_2)
		and target_5.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_2.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_6.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_7.getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_2.getCondition().(LogicalAndExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_3(Variable vnum_chans_195, BlockStmt target_4, NotExpr target_3) {
		target_3.getOperand().(VariableAccess).getTarget()=vnum_chans_195
		and target_3.getParent().(IfStmt).getThen()=target_4
}

predicate func_4(Parameter vwpc_191, BlockStmt target_4) {
		target_4.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("strcpy")
		and target_4.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="error_message"
		and target_4.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vwpc_191
		and target_4.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1) instanceof StringLiteral
		and target_4.getStmt(1).(ReturnStmt).getExpr().(Literal).getValue()="0"
}

predicate func_5(Parameter vwpc_191, ExprStmt target_5) {
		target_5.getExpr().(FunctionCall).getTarget().hasName("strcpy")
		and target_5.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="error_message"
		and target_5.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vwpc_191
		and target_5.getExpr().(FunctionCall).getArgument(1) instanceof StringLiteral
}

predicate func_6(Parameter vwpc_191, Parameter vconfig_191, ExprStmt target_6) {
		target_6.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="stream_version"
		and target_6.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vwpc_191
		and target_6.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="flags"
		and target_6.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconfig_191
		and target_6.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getCondition().(BitwiseAndExpr).getRightOperand().(Literal).getValue()="4194304"
		and target_6.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getThen().(Literal).getValue()="1031"
		and target_6.getExpr().(AssignExpr).getRValue().(ConditionalExpr).getElse().(Literal).getValue()="1040"
}

predicate func_7(Parameter vconfig_191, RelationalOperation target_7) {
		 (target_7 instanceof GEExpr or target_7 instanceof LEExpr)
		and target_7.getLesserOperand().(PointerFieldAccess).getTarget().getName()="sample_rate"
		and target_7.getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconfig_191
		and target_7.getGreaterOperand().(Literal).getValue()="0"
}

from Function func, Parameter vwpc_191, Parameter vconfig_191, Variable vnum_chans_195, StringLiteral target_0, NotExpr target_3, BlockStmt target_4, ExprStmt target_5, ExprStmt target_6, RelationalOperation target_7
where
func_0(func, target_0)
and not func_1(vnum_chans_195, target_4, target_3)
and not func_2(vwpc_191, vconfig_191, target_5, target_6, target_7, func)
and func_3(vnum_chans_195, target_4, target_3)
and func_4(vwpc_191, target_4)
and func_5(vwpc_191, target_5)
and func_6(vwpc_191, vconfig_191, target_6)
and func_7(vconfig_191, target_7)
and vwpc_191.getType().hasName("WavpackContext *")
and vconfig_191.getType().hasName("WavpackConfig *")
and vnum_chans_195.getType().hasName("int")
and vwpc_191.getParentScope+() = func
and vconfig_191.getParentScope+() = func
and vnum_chans_195.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
