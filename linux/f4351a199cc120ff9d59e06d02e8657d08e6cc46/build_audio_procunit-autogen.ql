/**
 * @name linux-f4351a199cc120ff9d59e06d02e8657d08e6cc46-build_audio_procunit
 * @id cpp/linux/f4351a199cc120ff9d59e06d02e8657d08e6cc46/build-audio-procunit
 * @description linux-f4351a199cc120ff9d59e06d02e8657d08e6cc46-build_audio_procunit 
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vnum_ins_2317, Function func) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vnum_ins_2317
		and target_0.getExpr().(AssignExpr).getRValue() instanceof PointerFieldAccess
		and (func.getEntryPoint().(BlockStmt).getStmt(11)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(11).getFollowingStmt()=target_0))
}

predicate func_1(Parameter vstate_2312, Parameter vunitid_2312, Parameter vname_2314, Variable vdesc_2316, Variable vnum_ins_2317, Function func) {
	exists(IfStmt target_1 |
		target_1.getCondition().(LogicalOrExpr).getAnOperand() instanceof RelationalOperation
		and target_1.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getTarget().getName()="bLength"
		and target_1.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdesc_2316
		and target_1.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vnum_ins_2317
		and target_1.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(FunctionCall).getTarget().hasName("uac_processing_unit_bControlSize")
		and target_1.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vdesc_2316
		and target_1.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="protocol"
		and target_1.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="mixer"
		and target_1.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vstate_2312
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("_dev_err")
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="dev"
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="dev"
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="chip"
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vstate_2312
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="invalid %s descriptor (id %d)\n"
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vname_2314
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vunitid_2312
		and target_1.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-22"
		and target_1.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(UnaryMinusExpr).getOperand().(Literal).getValue()="22"
		and (func.getEntryPoint().(BlockStmt).getStmt(12)=target_1 or func.getEntryPoint().(BlockStmt).getStmt(12).getFollowingStmt()=target_1))
}

predicate func_4(Variable vdesc_2316) {
	exists(PointerFieldAccess target_4 |
		target_4.getTarget().getName()="bNrInPins"
		and target_4.getQualifier().(VariableAccess).getTarget()=vdesc_2316)
}

predicate func_5(Variable vdesc_2316) {
	exists(RelationalOperation target_5 |
		 (target_5 instanceof GTExpr or target_5 instanceof LTExpr)
		and target_5.getLesserOperand().(PointerFieldAccess).getTarget().getName()="bLength"
		and target_5.getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdesc_2316
		and target_5.getGreaterOperand().(Literal).getValue()="13")
}

predicate func_6(Variable vdesc_2316, Variable vnum_ins_2317) {
	exists(RelationalOperation target_6 |
		 (target_6 instanceof GTExpr or target_6 instanceof LTExpr)
		and target_6.getLesserOperand().(PointerFieldAccess).getTarget().getName()="bLength"
		and target_6.getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdesc_2316
		and target_6.getGreaterOperand().(AddExpr).getAnOperand().(Literal).getValue()="13"
		and target_6.getGreaterOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vnum_ins_2317)
}

predicate func_7(Function func) {
	exists(Initializer target_7 |
		target_7.getExpr() instanceof PointerFieldAccess
		and target_7.getExpr().getEnclosingFunction() = func)
}

predicate func_8(Parameter vstate_2312, Parameter vunitid_2312, Parameter vname_2314, Variable vdesc_2316, Variable vnum_ins_2317) {
	exists(LogicalOrExpr target_8 |
		target_8.getAnOperand() instanceof RelationalOperation
		and target_8.getAnOperand() instanceof RelationalOperation
		and target_8.getParent().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getTarget().getName()="bLength"
		and target_8.getParent().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdesc_2316
		and target_8.getParent().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vnum_ins_2317
		and target_8.getParent().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(FunctionCall).getTarget().hasName("uac_processing_unit_bControlSize")
		and target_8.getParent().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vdesc_2316
		and target_8.getParent().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="protocol"
		and target_8.getParent().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="mixer"
		and target_8.getParent().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vstate_2312
		and target_8.getParent().(LogicalOrExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("_dev_err")
		and target_8.getParent().(LogicalOrExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="dev"
		and target_8.getParent().(LogicalOrExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="dev"
		and target_8.getParent().(LogicalOrExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="chip"
		and target_8.getParent().(LogicalOrExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vstate_2312
		and target_8.getParent().(LogicalOrExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="invalid %s descriptor (id %d)\n"
		and target_8.getParent().(LogicalOrExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vname_2314
		and target_8.getParent().(LogicalOrExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vunitid_2312
		and target_8.getParent().(LogicalOrExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(UnaryMinusExpr).getOperand().(Literal).getValue()="22")
}

predicate func_9(Parameter vstate_2312) {
	exists(PointerFieldAccess target_9 |
		target_9.getTarget().getName()="chip"
		and target_9.getQualifier().(VariableAccess).getTarget()=vstate_2312)
}

predicate func_10(Parameter vstate_2312, Parameter vunitid_2312, Parameter vname_2314) {
	exists(FunctionCall target_10 |
		target_10.getTarget().hasName("_dev_err")
		and target_10.getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="dev"
		and target_10.getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="dev"
		and target_10.getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="chip"
		and target_10.getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vstate_2312
		and target_10.getArgument(1).(StringLiteral).getValue()="invalid %s descriptor (id %d)\n"
		and target_10.getArgument(2).(VariableAccess).getTarget()=vname_2314
		and target_10.getArgument(3).(VariableAccess).getTarget()=vunitid_2312)
}

predicate func_12(Parameter vstate_2312, Variable vdesc_2316, Variable vnum_ins_2317, Variable vi_2320, Variable verr_2320) {
	exists(RelationalOperation target_12 |
		 (target_12 instanceof GTExpr or target_12 instanceof LTExpr)
		and target_12.getLesserOperand().(VariableAccess).getTarget()=vi_2320
		and target_12.getGreaterOperand().(VariableAccess).getTarget()=vnum_ins_2317
		and target_12.getParent().(ForStmt).getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=verr_2320
		and target_12.getParent().(ForStmt).getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("parse_audio_unit")
		and target_12.getParent().(ForStmt).getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vstate_2312
		and target_12.getParent().(ForStmt).getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="baSourceID"
		and target_12.getParent().(ForStmt).getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdesc_2316
		and target_12.getParent().(ForStmt).getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_2320
		and target_12.getParent().(ForStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=verr_2320
		and target_12.getParent().(ForStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="0"
		and target_12.getParent().(ForStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(ReturnStmt).getExpr().(VariableAccess).getTarget()=verr_2320)
}

from Function func, Parameter vstate_2312, Parameter vunitid_2312, Parameter vname_2314, Variable vdesc_2316, Variable vnum_ins_2317, Variable vi_2320, Variable verr_2320
where
not func_0(vnum_ins_2317, func)
and not func_1(vstate_2312, vunitid_2312, vname_2314, vdesc_2316, vnum_ins_2317, func)
and func_4(vdesc_2316)
and func_5(vdesc_2316)
and func_6(vdesc_2316, vnum_ins_2317)
and func_7(func)
and func_8(vstate_2312, vunitid_2312, vname_2314, vdesc_2316, vnum_ins_2317)
and vstate_2312.getType().hasName("mixer_build *")
and func_9(vstate_2312)
and vunitid_2312.getType().hasName("int")
and func_10(vstate_2312, vunitid_2312, vname_2314)
and vname_2314.getType().hasName("char *")
and vdesc_2316.getType().hasName("uac_processing_unit_descriptor *")
and vnum_ins_2317.getType().hasName("int")
and func_12(vstate_2312, vdesc_2316, vnum_ins_2317, vi_2320, verr_2320)
and vi_2320.getType().hasName("int")
and verr_2320.getType().hasName("int")
and vstate_2312.getParentScope+() = func
and vunitid_2312.getParentScope+() = func
and vname_2314.getParentScope+() = func
and vdesc_2316.getParentScope+() = func
and vnum_ins_2317.getParentScope+() = func
and vi_2320.getParentScope+() = func
and verr_2320.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
