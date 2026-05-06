#---------------------------#
#---------- SDS 315 --------#
#------- lm vs anova -------#
#--Last updated Apr 13, 26--#
#---------------------------#


setwd('...')
set.seed(1)

library(tidyverse)
library(mosaic)
library(ggplot2)
library(effectsize)

rxntime <- read.csv('rxntime.csv')

# fit a linear model
games_model1 = lm(PictureTarget.RT ~ Littered + FarAway, data=rxntime)
summary(games_model1)
anova(games_model1)


# calculate overall mean
mean(~PictureTarget.RT, data=rxntime)

# calculate mean reaction time for each subject
subject_means = aggregate(PictureTarget.RT~Subject, FUN=mean, data=rxntime)
colnames(subject_means) <- c("Subject","mean_RT")

# sort the subjects by mean reaction time
subject_means %>%
  arrange(mean_RT)

# Subject is currently a numeric variable 
ggplot(rxntime) + 
  geom_boxplot(aes(x=Subject, y=PictureTarget.RT))

# tell R that Subject is categorical, not numerical
rxntime = mutate(rxntime, Subject = factor(Subject))
ggplot(rxntime) + 
  geom_boxplot(aes(x=Subject, y=PictureTarget.RT))

# fit a linear model with subject effects
games_model2 = lm(PictureTarget.RT ~ Littered + FarAway + Subject, data=rxntime)
summary(games_model2)
anova(games_model2)


# fit a linear model with interactions but NO subject effects
games_model3 = lm(PictureTarget.RT ~ Littered + FarAway + Littered * FarAway, data=rxntime)
summary(games_model3)
anova(games_model3)


# fit a linear model with interactions AND subject effects
games_model4 = lm(PictureTarget.RT ~ Littered + FarAway + Littered * FarAway +  Subject, data=rxntime)
summary(games_model4)
anova(games_model4)
eta_squared(games_model4, partial=FALSE)



