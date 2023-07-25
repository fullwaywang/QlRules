/**
 * @name ffmpeg-e1219cdaf9fb4bc8cea410e1caf802373c1bfe51-shorts2str
 * @id cpp/ffmpeg/e1219cdaf9fb4bc8cea410e1caf802373c1bfe51/shorts2str
 * @description ffmpeg-e1219cdaf9fb4bc8cea410e1caf802373c1bfe51-libavcodec/tiff.c-shorts2str CVE-2013-0874
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func, Literal target_0) {
		target_0.getValue()="5"
		and not target_0.getValue()="2147483647"
		and target_0.getParent().(AddExpr).getParent().(MulExpr).getLeftOperand().(AddExpr).getAnOperand() instanceof FunctionCall
		and target_0.getEnclosingFunction() = func
}

predicate func_1(Function func, Literal target_1) {
		target_1.getValue()="5"
		and not target_1.getValue()="1"
		and target_1.getParent().(AddExpr).getParent().(FunctionCall).getArgument(1) instanceof AddExpr
		and target_1.getEnclosingFunction() = func
}

predicate func_2(Function func) {
	exists(AssignExpr target_2 |
		target_2.getLValue().(VariableAccess).getType().hasName("uint64_t")
		and target_2.getRValue().(AddExpr).getAnOperand().(Literal).getValue()="7"
		and target_2.getRValue().(AddExpr).getAnOperand() instanceof FunctionCall
		and target_2.getEnclosingFunction() = func)
}

predicate func_3(Parameter vcount_241, MulExpr target_13, RelationalOperation target_14, Function func) {
	exists(IfStmt target_3 |
		target_3.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vcount_241
		and target_3.getCondition().(RelationalOperation).getLesserOperand().(DivExpr).getLeftOperand().(SubExpr).getValue()="2147483646"
		and target_3.getCondition().(RelationalOperation).getLesserOperand().(DivExpr).getRightOperand().(VariableAccess).getType().hasName("uint64_t")
		and target_3.getThen().(ReturnStmt).getExpr().(Literal).getValue()="0"
		and (func.getEntryPoint().(BlockStmt).getStmt(5)=target_3 or func.getEntryPoint().(BlockStmt).getStmt(5).getFollowingStmt()=target_3)
		and target_13.getRightOperand().(VariableAccess).getLocation().isBefore(target_3.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation())
		and target_3.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation().isBefore(target_14.getGreaterOperand().(VariableAccess).getLocation()))
}

predicate func_4(Parameter vcount_241, Variable vap_244, NotExpr target_15, Function func) {
	exists(ExprStmt target_4 |
		target_4.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vap_244
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("av_malloc")
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(AddExpr).getAnOperand().(MulExpr).getLeftOperand().(VariableAccess).getType().hasName("uint64_t")
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(AddExpr).getAnOperand().(MulExpr).getRightOperand().(VariableAccess).getTarget()=vcount_241
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(AddExpr).getAnOperand().(Literal).getValue()="1"
		and (func.getEntryPoint().(BlockStmt).getStmt(6)=target_4 or func.getEntryPoint().(BlockStmt).getStmt(6).getFollowingStmt()=target_4)
		and target_4.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_15.getOperand().(VariableAccess).getLocation()))
}

predicate func_9(Variable vap0_244, Variable vl_1_252, ExprStmt target_16, ExprStmt target_17, ExprStmt target_18) {
	exists(IfStmt target_9 |
		target_9.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vl_1_252
		and target_9.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getType().hasName("uint64_t")
		and target_9.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("av_free")
		and target_9.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vap0_244
		and target_9.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(Literal).getValue()="0"
		and target_16.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_9.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_9.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_17.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getLocation())
		and target_9.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation().isBefore(target_18.getExpr().(AssignPointerAddExpr).getRValue().(VariableAccess).getLocation()))
}

predicate func_10(Parameter vcount_241, Parameter vsep_241, FunctionCall target_10) {
		target_10.getTarget().hasName("strlen")
		and target_10.getArgument(0).(VariableAccess).getTarget()=vsep_241
		and target_10.getParent().(AddExpr).getParent().(MulExpr).getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("av_malloc")
		and target_10.getParent().(AddExpr).getParent().(MulExpr).getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(MulExpr).getLeftOperand().(AddExpr).getAnOperand() instanceof Literal
		and target_10.getParent().(AddExpr).getParent().(MulExpr).getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(MulExpr).getRightOperand().(VariableAccess).getTarget()=vcount_241
}

predicate func_12(Parameter vsep_241, Variable vap_244, AddExpr target_12) {
		target_12.getAnOperand() instanceof Literal
		and target_12.getAnOperand().(FunctionCall).getTarget().hasName("strlen")
		and target_12.getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsep_241
		and target_12.getParent().(FunctionCall).getParent().(Initializer).getExpr().(FunctionCall).getTarget().hasName("snprintf")
		and target_12.getParent().(FunctionCall).getParent().(Initializer).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vap_244
		and target_12.getParent().(FunctionCall).getParent().(Initializer).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="%d%s"
		and target_12.getParent().(FunctionCall).getParent().(Initializer).getExpr().(FunctionCall).getArgument(3).(ArrayExpr).getArrayBase().(VariableAccess).getTarget().getType().hasName("int16_t *")
		and target_12.getParent().(FunctionCall).getParent().(Initializer).getExpr().(FunctionCall).getArgument(3).(ArrayExpr).getArrayOffset().(VariableAccess).getTarget().getType().hasName("int")
		and target_12.getParent().(FunctionCall).getParent().(Initializer).getExpr().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vsep_241
}

predicate func_13(Parameter vcount_241, MulExpr target_13) {
		target_13.getLeftOperand().(AddExpr).getAnOperand() instanceof Literal
		and target_13.getLeftOperand().(AddExpr).getAnOperand() instanceof FunctionCall
		and target_13.getRightOperand().(VariableAccess).getTarget()=vcount_241
}

predicate func_14(Parameter vcount_241, RelationalOperation target_14) {
		 (target_14 instanceof GTExpr or target_14 instanceof LTExpr)
		and target_14.getLesserOperand().(VariableAccess).getTarget().getType().hasName("int")
		and target_14.getGreaterOperand().(VariableAccess).getTarget()=vcount_241
}

predicate func_15(Variable vap_244, NotExpr target_15) {
		target_15.getOperand().(VariableAccess).getTarget()=vap_244
}

predicate func_16(Variable vap_244, Variable vap0_244, ExprStmt target_16) {
		target_16.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vap0_244
		and target_16.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vap_244
}

predicate func_17(Parameter vsep_241, Variable vap0_244, ExprStmt target_17) {
		target_17.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vap0_244
		and target_17.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(SubExpr).getLeftOperand().(FunctionCall).getTarget().hasName("strlen")
		and target_17.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(SubExpr).getLeftOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vap0_244
		and target_17.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(SubExpr).getRightOperand().(FunctionCall).getTarget().hasName("strlen")
		and target_17.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(SubExpr).getRightOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsep_241
		and target_17.getExpr().(AssignExpr).getRValue().(CharLiteral).getValue()="0"
}

predicate func_18(Variable vap_244, Variable vl_1_252, ExprStmt target_18) {
		target_18.getExpr().(AssignPointerAddExpr).getLValue().(VariableAccess).getTarget()=vap_244
		and target_18.getExpr().(AssignPointerAddExpr).getRValue().(VariableAccess).getTarget()=vl_1_252
}

from Function func, Parameter vcount_241, Parameter vsep_241, Variable vap_244, Variable vap0_244, Variable vl_1_252, Literal target_0, Literal target_1, FunctionCall target_10, AddExpr target_12, MulExpr target_13, RelationalOperation target_14, NotExpr target_15, ExprStmt target_16, ExprStmt target_17, ExprStmt target_18
where
func_0(func, target_0)
and func_1(func, target_1)
and not func_2(func)
and not func_3(vcount_241, target_13, target_14, func)
and not func_4(vcount_241, vap_244, target_15, func)
and not func_9(vap0_244, vl_1_252, target_16, target_17, target_18)
and func_10(vcount_241, vsep_241, target_10)
and func_12(vsep_241, vap_244, target_12)
and func_13(vcount_241, target_13)
and func_14(vcount_241, target_14)
and func_15(vap_244, target_15)
and func_16(vap_244, vap0_244, target_16)
and func_17(vsep_241, vap0_244, target_17)
and func_18(vap_244, vl_1_252, target_18)
and vcount_241.getType().hasName("int")
and vsep_241.getType().hasName("const char *")
and vap_244.getType().hasName("char *")
and vap0_244.getType().hasName("char *")
and vl_1_252.getType().hasName("int")
and vcount_241.getFunction() = func
and vsep_241.getFunction() = func
and vap_244.(LocalVariable).getFunction() = func
and vap0_244.(LocalVariable).getFunction() = func
and vl_1_252.(LocalVariable).getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
