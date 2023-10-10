/**
 * @name openssl-578b956fe741bf8e84055547b1e83c28dd902c73-_dopr
 * @id cpp/openssl/578b956fe741bf8e84055547b1e83c28dd902c73/-dopr
 * @description openssl-578b956fe741bf8e84055547b1e83c28dd902c73-_dopr CVE-2016-0799
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vsbuffer_169, Parameter vbuffer_170, Parameter vmaxlen_171, Variable vch_174) {
	exists(IfStmt target_0 |
		target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("doapr_outch")
		and target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsbuffer_169
		and target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vbuffer_170
		and target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(2) instanceof AddressOfExpr
		and target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vmaxlen_171
		and target_0.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vch_174
		and target_0.getThen().(ReturnStmt).getExpr().(Literal).getValue()="0"
		and target_0.getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vch_174
		and target_0.getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(CharLiteral).getValue()="37")
}

predicate func_1(Parameter vsbuffer_169, Parameter vbuffer_170, Parameter vmaxlen_171, Variable vch_174, Variable vvalue_175, Variable vmin_178, Variable vmax_179, Variable vflags_181) {
	exists(IfStmt target_1 |
		target_1.getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("fmtint")
		and target_1.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsbuffer_169
		and target_1.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vbuffer_170
		and target_1.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(2) instanceof AddressOfExpr
		and target_1.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vmaxlen_171
		and target_1.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vvalue_175
		and target_1.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(5) instanceof Literal
		and target_1.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(6).(VariableAccess).getTarget()=vmin_178
		and target_1.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(7).(VariableAccess).getTarget()=vmax_179
		and target_1.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(8).(VariableAccess).getTarget()=vflags_181
		and target_1.getThen().(ReturnStmt).getExpr().(Literal).getValue()="0"
		and target_1.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr().(VariableAccess).getTarget()=vch_174)
}

predicate func_2(Parameter vsbuffer_169, Parameter vbuffer_170, Parameter vmaxlen_171, Variable vch_174, Variable vvalue_175, Variable vmin_178, Variable vmax_179, Variable vflags_181) {
	exists(IfStmt target_2 |
		target_2.getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("fmtint")
		and target_2.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsbuffer_169
		and target_2.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vbuffer_170
		and target_2.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(2) instanceof AddressOfExpr
		and target_2.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vmaxlen_171
		and target_2.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vvalue_175
		and target_2.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(5) instanceof ConditionalExpr
		and target_2.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(6).(VariableAccess).getTarget()=vmin_178
		and target_2.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(7).(VariableAccess).getTarget()=vmax_179
		and target_2.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(8).(VariableAccess).getTarget()=vflags_181
		and target_2.getThen().(ReturnStmt).getExpr().(Literal).getValue()="0"
		and target_2.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr().(VariableAccess).getTarget()=vch_174)
}

predicate func_3(Parameter vsbuffer_169, Parameter vbuffer_170, Parameter vmaxlen_171, Variable vch_174, Variable vfvalue_176, Variable vmin_178, Variable vmax_179, Variable vflags_181) {
	exists(IfStmt target_3 |
		target_3.getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("fmtfp")
		and target_3.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsbuffer_169
		and target_3.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vbuffer_170
		and target_3.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(2) instanceof AddressOfExpr
		and target_3.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vmaxlen_171
		and target_3.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vfvalue_176
		and target_3.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(5).(VariableAccess).getTarget()=vmin_178
		and target_3.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(6).(VariableAccess).getTarget()=vmax_179
		and target_3.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(7).(VariableAccess).getTarget()=vflags_181
		and target_3.getThen().(ReturnStmt).getExpr().(Literal).getValue()="0"
		and target_3.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr().(VariableAccess).getTarget()=vch_174)
}

predicate func_4(Parameter vsbuffer_169, Parameter vbuffer_170, Parameter vmaxlen_171, Variable vch_174) {
	exists(IfStmt target_4 |
		target_4.getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("doapr_outch")
		and target_4.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsbuffer_169
		and target_4.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vbuffer_170
		and target_4.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(2) instanceof AddressOfExpr
		and target_4.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vmaxlen_171
		and target_4.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(4) instanceof BuiltInVarArg
		and target_4.getThen().(ReturnStmt).getExpr().(Literal).getValue()="0"
		and target_4.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr().(VariableAccess).getTarget()=vch_174)
}

predicate func_5(Parameter vsbuffer_169, Parameter vbuffer_170, Parameter vmaxlen_171, Variable vch_174, Variable vstrvalue_177, Variable vmin_178, Variable vmax_179, Variable vflags_181) {
	exists(IfStmt target_5 |
		target_5.getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("fmtstr")
		and target_5.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsbuffer_169
		and target_5.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vbuffer_170
		and target_5.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(2) instanceof AddressOfExpr
		and target_5.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vmaxlen_171
		and target_5.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vstrvalue_177
		and target_5.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(5).(VariableAccess).getTarget()=vflags_181
		and target_5.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(6).(VariableAccess).getTarget()=vmin_178
		and target_5.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(7).(VariableAccess).getTarget()=vmax_179
		and target_5.getThen().(ReturnStmt).getExpr().(Literal).getValue()="0"
		and target_5.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr().(VariableAccess).getTarget()=vch_174)
}

predicate func_6(Parameter vsbuffer_169, Parameter vbuffer_170, Parameter vmaxlen_171, Variable vch_174, Variable vvalue_175, Variable vmin_178, Variable vmax_179) {
	exists(IfStmt target_6 |
		target_6.getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("fmtint")
		and target_6.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsbuffer_169
		and target_6.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vbuffer_170
		and target_6.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(2) instanceof AddressOfExpr
		and target_6.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vmaxlen_171
		and target_6.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vvalue_175
		and target_6.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(5) instanceof Literal
		and target_6.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(6).(VariableAccess).getTarget()=vmin_178
		and target_6.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(7).(VariableAccess).getTarget()=vmax_179
		and target_6.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(8) instanceof BitwiseOrExpr
		and target_6.getThen().(ReturnStmt).getExpr().(Literal).getValue()="0"
		and target_6.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr().(VariableAccess).getTarget()=vch_174)
}

predicate func_8(Parameter vsbuffer_169, Parameter vbuffer_170, Parameter vmaxlen_171, Function func) {
	exists(IfStmt target_8 |
		target_8.getCondition().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("doapr_outch")
		and target_8.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsbuffer_169
		and target_8.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vbuffer_170
		and target_8.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(2) instanceof AddressOfExpr
		and target_8.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vmaxlen_171
		and target_8.getCondition().(NotExpr).getOperand().(FunctionCall).getArgument(4) instanceof CharLiteral
		and target_8.getThen().(ReturnStmt).getExpr().(Literal).getValue()="0"
		and (func.getEntryPoint().(BlockStmt).getStmt(17)=target_8 or func.getEntryPoint().(BlockStmt).getStmt(17).getFollowingStmt()=target_8))
}

predicate func_10(Variable vcurrlen_183) {
	exists(AddressOfExpr target_10 |
		target_10.getOperand().(VariableAccess).getTarget()=vcurrlen_183
		and target_10.getParent().(FunctionCall).getParent().(ExprStmt).getExpr() instanceof FunctionCall)
}

predicate func_13(Variable vch_174) {
	exists(ConditionalExpr target_13 |
		target_13.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vch_174
		and target_13.getCondition().(EqualityOperation).getAnOperand().(CharLiteral).getValue()="111"
		and target_13.getThen().(Literal).getValue()="8"
		and target_13.getElse().(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vch_174
		and target_13.getElse().(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(CharLiteral).getValue()="117"
		and target_13.getElse().(ConditionalExpr).getThen().(Literal).getValue()="10"
		and target_13.getElse().(ConditionalExpr).getElse().(Literal).getValue()="16"
		and target_13.getParent().(FunctionCall).getParent().(ExprStmt).getExpr() instanceof FunctionCall)
}

predicate func_16(Parameter vargs_172) {
	exists(BuiltInVarArg target_16 |
		target_16.getVAList().(VariableAccess).getTarget()=vargs_172)
}

predicate func_19(Variable vflags_181) {
	exists(BitwiseOrExpr target_19 |
		target_19.getLeftOperand().(VariableAccess).getTarget()=vflags_181
		and target_19.getRightOperand().(BinaryBitwiseOperation).getValue()="8"
		and target_19.getParent().(FunctionCall).getParent().(ExprStmt).getExpr() instanceof FunctionCall)
}

predicate func_30(Function func) {
	exists(Literal target_30 |
		target_30.getValue()="10"
		and target_30.getEnclosingFunction() = func)
}

predicate func_62(Function func) {
	exists(Literal target_62 |
		target_62.getValue()="16"
		and target_62.getEnclosingFunction() = func)
}

predicate func_72(Function func) {
	exists(CharLiteral target_72 |
		target_72.getValue()="0"
		and target_72.getEnclosingFunction() = func)
}

predicate func_73(Parameter vsbuffer_169, Parameter vbuffer_170, Parameter vmaxlen_171, Variable vch_174) {
	exists(ExprStmt target_73 |
		target_73.getExpr().(FunctionCall).getTarget().hasName("doapr_outch")
		and target_73.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsbuffer_169
		and target_73.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vbuffer_170
		and target_73.getExpr().(FunctionCall).getArgument(2) instanceof AddressOfExpr
		and target_73.getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vmaxlen_171
		and target_73.getExpr().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vch_174
		and target_73.getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vch_174
		and target_73.getParent().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(CharLiteral).getValue()="37")
}

predicate func_74(Parameter vsbuffer_169, Parameter vbuffer_170, Parameter vmaxlen_171, Variable vch_174, Variable vvalue_175, Variable vmin_178, Variable vmax_179, Variable vflags_181) {
	exists(ExprStmt target_74 |
		target_74.getExpr().(FunctionCall).getTarget().hasName("fmtint")
		and target_74.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsbuffer_169
		and target_74.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vbuffer_170
		and target_74.getExpr().(FunctionCall).getArgument(2) instanceof AddressOfExpr
		and target_74.getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vmaxlen_171
		and target_74.getExpr().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vvalue_175
		and target_74.getExpr().(FunctionCall).getArgument(5) instanceof Literal
		and target_74.getExpr().(FunctionCall).getArgument(6).(VariableAccess).getTarget()=vmin_178
		and target_74.getExpr().(FunctionCall).getArgument(7).(VariableAccess).getTarget()=vmax_179
		and target_74.getExpr().(FunctionCall).getArgument(8).(VariableAccess).getTarget()=vflags_181
		and target_74.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr().(VariableAccess).getTarget()=vch_174)
}

predicate func_75(Parameter vsbuffer_169, Parameter vbuffer_170, Parameter vmaxlen_171, Variable vch_174, Variable vvalue_175, Variable vmin_178, Variable vmax_179, Variable vflags_181) {
	exists(ExprStmt target_75 |
		target_75.getExpr().(FunctionCall).getTarget().hasName("fmtint")
		and target_75.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsbuffer_169
		and target_75.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vbuffer_170
		and target_75.getExpr().(FunctionCall).getArgument(2) instanceof AddressOfExpr
		and target_75.getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vmaxlen_171
		and target_75.getExpr().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vvalue_175
		and target_75.getExpr().(FunctionCall).getArgument(5) instanceof ConditionalExpr
		and target_75.getExpr().(FunctionCall).getArgument(6).(VariableAccess).getTarget()=vmin_178
		and target_75.getExpr().(FunctionCall).getArgument(7).(VariableAccess).getTarget()=vmax_179
		and target_75.getExpr().(FunctionCall).getArgument(8).(VariableAccess).getTarget()=vflags_181
		and target_75.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr().(VariableAccess).getTarget()=vch_174)
}

predicate func_76(Parameter vsbuffer_169, Parameter vbuffer_170, Parameter vmaxlen_171, Variable vch_174, Variable vfvalue_176, Variable vmin_178, Variable vmax_179, Variable vflags_181) {
	exists(ExprStmt target_76 |
		target_76.getExpr().(FunctionCall).getTarget().hasName("fmtfp")
		and target_76.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsbuffer_169
		and target_76.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vbuffer_170
		and target_76.getExpr().(FunctionCall).getArgument(2) instanceof AddressOfExpr
		and target_76.getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vmaxlen_171
		and target_76.getExpr().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vfvalue_176
		and target_76.getExpr().(FunctionCall).getArgument(5).(VariableAccess).getTarget()=vmin_178
		and target_76.getExpr().(FunctionCall).getArgument(6).(VariableAccess).getTarget()=vmax_179
		and target_76.getExpr().(FunctionCall).getArgument(7).(VariableAccess).getTarget()=vflags_181
		and target_76.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr().(VariableAccess).getTarget()=vch_174)
}

predicate func_77(Parameter vsbuffer_169, Parameter vbuffer_170, Parameter vmaxlen_171, Variable vch_174) {
	exists(ExprStmt target_77 |
		target_77.getExpr().(FunctionCall).getTarget().hasName("doapr_outch")
		and target_77.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsbuffer_169
		and target_77.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vbuffer_170
		and target_77.getExpr().(FunctionCall).getArgument(2) instanceof AddressOfExpr
		and target_77.getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vmaxlen_171
		and target_77.getExpr().(FunctionCall).getArgument(4) instanceof BuiltInVarArg
		and target_77.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr().(VariableAccess).getTarget()=vch_174)
}

predicate func_78(Parameter vsbuffer_169, Parameter vbuffer_170, Parameter vmaxlen_171, Variable vch_174, Variable vstrvalue_177, Variable vmin_178, Variable vmax_179, Variable vflags_181) {
	exists(ExprStmt target_78 |
		target_78.getExpr().(FunctionCall).getTarget().hasName("fmtstr")
		and target_78.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsbuffer_169
		and target_78.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vbuffer_170
		and target_78.getExpr().(FunctionCall).getArgument(2) instanceof AddressOfExpr
		and target_78.getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vmaxlen_171
		and target_78.getExpr().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vstrvalue_177
		and target_78.getExpr().(FunctionCall).getArgument(5).(VariableAccess).getTarget()=vflags_181
		and target_78.getExpr().(FunctionCall).getArgument(6).(VariableAccess).getTarget()=vmin_178
		and target_78.getExpr().(FunctionCall).getArgument(7).(VariableAccess).getTarget()=vmax_179
		and target_78.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr().(VariableAccess).getTarget()=vch_174)
}

predicate func_79(Parameter vsbuffer_169, Parameter vbuffer_170, Parameter vmaxlen_171, Variable vch_174, Variable vvalue_175, Variable vmin_178, Variable vmax_179) {
	exists(ExprStmt target_79 |
		target_79.getExpr().(FunctionCall).getTarget().hasName("fmtint")
		and target_79.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsbuffer_169
		and target_79.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vbuffer_170
		and target_79.getExpr().(FunctionCall).getArgument(2) instanceof AddressOfExpr
		and target_79.getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vmaxlen_171
		and target_79.getExpr().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vvalue_175
		and target_79.getExpr().(FunctionCall).getArgument(5) instanceof Literal
		and target_79.getExpr().(FunctionCall).getArgument(6).(VariableAccess).getTarget()=vmin_178
		and target_79.getExpr().(FunctionCall).getArgument(7).(VariableAccess).getTarget()=vmax_179
		and target_79.getExpr().(FunctionCall).getArgument(8) instanceof BitwiseOrExpr
		and target_79.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr().(VariableAccess).getTarget()=vch_174)
}

predicate func_81(Parameter vsbuffer_169, Parameter vbuffer_170, Parameter vmaxlen_171, Function func) {
	exists(ExprStmt target_81 |
		target_81.getExpr().(FunctionCall).getTarget().hasName("doapr_outch")
		and target_81.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vsbuffer_169
		and target_81.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vbuffer_170
		and target_81.getExpr().(FunctionCall).getArgument(2) instanceof AddressOfExpr
		and target_81.getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vmaxlen_171
		and target_81.getExpr().(FunctionCall).getArgument(4) instanceof CharLiteral
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_81)
}

from Function func, Parameter vsbuffer_169, Parameter vbuffer_170, Parameter vmaxlen_171, Parameter vargs_172, Variable vch_174, Variable vvalue_175, Variable vfvalue_176, Variable vstrvalue_177, Variable vmin_178, Variable vmax_179, Variable vflags_181, Variable vcurrlen_183
where
not func_0(vsbuffer_169, vbuffer_170, vmaxlen_171, vch_174)
and not func_1(vsbuffer_169, vbuffer_170, vmaxlen_171, vch_174, vvalue_175, vmin_178, vmax_179, vflags_181)
and not func_2(vsbuffer_169, vbuffer_170, vmaxlen_171, vch_174, vvalue_175, vmin_178, vmax_179, vflags_181)
and not func_3(vsbuffer_169, vbuffer_170, vmaxlen_171, vch_174, vfvalue_176, vmin_178, vmax_179, vflags_181)
and not func_4(vsbuffer_169, vbuffer_170, vmaxlen_171, vch_174)
and not func_5(vsbuffer_169, vbuffer_170, vmaxlen_171, vch_174, vstrvalue_177, vmin_178, vmax_179, vflags_181)
and not func_6(vsbuffer_169, vbuffer_170, vmaxlen_171, vch_174, vvalue_175, vmin_178, vmax_179)
and not func_8(vsbuffer_169, vbuffer_170, vmaxlen_171, func)
and func_10(vcurrlen_183)
and func_13(vch_174)
and func_16(vargs_172)
and func_19(vflags_181)
and func_30(func)
and func_62(func)
and func_72(func)
and func_73(vsbuffer_169, vbuffer_170, vmaxlen_171, vch_174)
and func_74(vsbuffer_169, vbuffer_170, vmaxlen_171, vch_174, vvalue_175, vmin_178, vmax_179, vflags_181)
and func_75(vsbuffer_169, vbuffer_170, vmaxlen_171, vch_174, vvalue_175, vmin_178, vmax_179, vflags_181)
and func_76(vsbuffer_169, vbuffer_170, vmaxlen_171, vch_174, vfvalue_176, vmin_178, vmax_179, vflags_181)
and func_77(vsbuffer_169, vbuffer_170, vmaxlen_171, vch_174)
and func_78(vsbuffer_169, vbuffer_170, vmaxlen_171, vch_174, vstrvalue_177, vmin_178, vmax_179, vflags_181)
and func_79(vsbuffer_169, vbuffer_170, vmaxlen_171, vch_174, vvalue_175, vmin_178, vmax_179)
and func_81(vsbuffer_169, vbuffer_170, vmaxlen_171, func)
and vsbuffer_169.getType().hasName("char **")
and vbuffer_170.getType().hasName("char **")
and vmaxlen_171.getType().hasName("size_t *")
and vargs_172.getType().hasName("va_list")
and vch_174.getType().hasName("char")
and vvalue_175.getType().hasName("long")
and vfvalue_176.getType().hasName("double")
and vstrvalue_177.getType().hasName("char *")
and vmin_178.getType().hasName("int")
and vmax_179.getType().hasName("int")
and vflags_181.getType().hasName("int")
and vcurrlen_183.getType().hasName("size_t")
and vsbuffer_169.getParentScope+() = func
and vbuffer_170.getParentScope+() = func
and vmaxlen_171.getParentScope+() = func
and vargs_172.getParentScope+() = func
and vch_174.getParentScope+() = func
and vvalue_175.getParentScope+() = func
and vfvalue_176.getParentScope+() = func
and vstrvalue_177.getParentScope+() = func
and vmin_178.getParentScope+() = func
and vmax_179.getParentScope+() = func
and vflags_181.getParentScope+() = func
and vcurrlen_183.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
